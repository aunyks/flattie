use crate::models::User;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http;
use actix_web::{Error, HttpMessage, HttpResponse};
use futures::future::{ok, FutureExt, LocalBoxFuture, Ready};
use sqlx::PgPool;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::rc::Rc;
use std::task::{Context, Poll};

pub struct IsAuthenticated;

impl<S, B> Transform<S> for IsAuthenticated
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S: 'static,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = IsAuthenticatedMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(IsAuthenticatedMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct IsAuthenticatedMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S, B> Service for IsAuthenticatedMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S: 'static,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.borrow_mut().poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let db_connection = match req.app_data::<actix_web::web::Data<PgPool>>() {
            Some(db_conn) => db_conn,
            None => {
                return async move {
                    Err(actix_web::error::InternalError::new(
                        "Could not access database connection while enforcing auth state!",
                        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into())
                }
                .boxed_local()
            }
        };
        let db_connection = db_connection.clone();

        let login_token = match req.cookie("login_token") {
            Some(token_cookie) => String::from(token_cookie.value()),
            None => {
                return async move {
                    let res = req.into_response(
                        HttpResponse::Found()
                            .header(
                                http::header::LOCATION,
                                crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                            )
                            .finish()
                            .into_body(),
                    );
                    Ok(res)
                }
                .boxed_local();
            }
        };

        let mut service = Rc::clone(&self.service);
        async move {
            if User::with_login_token(login_token, &db_connection)
                .await
                .is_err()
            {
                let res = req.into_response(
                    HttpResponse::Found()
                        .header(
                            http::header::LOCATION,
                            crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                        )
                        .finish()
                        .into_body(),
                );
                Ok(res)
            } else {
                let fut = service.borrow_mut().call(req);
                let res = fut.await?;
                Ok(res)
            }
        }
        .boxed_local()
    }
}
