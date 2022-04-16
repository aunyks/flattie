use actix::prelude::*;
use actix_web::{
    web::{self, Bytes},
    Error, HttpRequest, HttpResponse,
};
use actix_web_actors::ws;
use log::{debug, info};
use std::time::{Duration, Instant};

// How often to poll the client to make sure
// the connection state is alive.
//
// To configure this at compile time, do something like
// the following
// Duration::from_secs(std::option_env!("hi").unwrap().parse::<u64>().unwrap());
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

// How long we wait for the client to respond
// to a heartbeat until we close the connection ourselves
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct EchoSocket {
    latest_hb: Instant,
}

impl Actor for EchoSocket {
    type Context = ws::WebsocketContext<Self>;

    // Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

impl EchoSocket {
    pub fn new() -> Self {
        Self {
            latest_hb: Instant::now(),
        }
    }

    /// helper method that sends ping to client every second.
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.latest_hb) > CLIENT_TIMEOUT {
                info!("Websocket client timed out!");
                // Stop the actor and
                // close the connection
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }
}

/// Handler for `ws::Message`
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for EchoSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        // process websocket messages
        debug!("WS: {:?}", msg);
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.latest_hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.latest_hb = Instant::now();
            }
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => {
                match bin.as_ref() {
                    [0x55] => {
                        info!("0x55 was sent!");
                        ctx.binary(Bytes::copy_from_slice(&[0x7c]));
                    }
                    _ => {}
                };
                ctx.binary(bin)
            }
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

pub async fn echo_ws(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    ws::start(EchoSocket::new(), &req, stream)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use actix_web::test;
    use actix_web::App;
    use futures::{SinkExt, StreamExt};

    #[actix_rt::test]
    async fn test_echo_socket_text() {
        let mut srv = test::start(|| {
            App::new().service(web::resource("/").to(
                |req: HttpRequest, stream: web::Payload| async move {
                    ws::start(EchoSocket::new(), &req, stream)
                },
            ))
        });

        let mut ws_buffer = srv.ws().await.unwrap();

        // Send text
        ws_buffer
            .send(ws::Message::Text("example text".to_string()))
            .await
            .unwrap();

        // Make sure we get it back
        let text_response = ws_buffer.next().await.unwrap().unwrap();
        assert_eq!(
            text_response,
            ws::Frame::Text(Bytes::from_static(b"example text"))
        );
    }

    #[actix_rt::test]
    async fn test_echo_socket_ping() {
        let mut srv = test::start(|| {
            App::new().service(web::resource("/").to(
                |req: HttpRequest, stream: web::Payload| async move {
                    ws::start(EchoSocket::new(), &req, stream)
                },
            ))
        });

        let mut ws_buffer = srv.ws().await.unwrap();

        // Send a ping
        ws_buffer
            .send(ws::Message::Ping(Bytes::from_static(b"")))
            .await
            .unwrap();

        // Make sure we get a pong back
        let ping_response = ws_buffer.next().await.unwrap().unwrap();
        assert_eq!(ping_response, ws::Frame::Pong(Bytes::from_static(b"")));
    }

    #[actix_rt::test]
    async fn test_echo_socket_pong() {
        let mut srv = test::start(|| {
            App::new().service(web::resource("/").to(
                |req: HttpRequest, stream: web::Payload| async move {
                    ws::start(EchoSocket::new(), &req, stream)
                },
            ))
        });

        let mut ws_buffer = srv.ws().await.unwrap();

        // Send a pong
        ws_buffer
            .send(ws::Message::Pong(Bytes::from_static(b"")))
            .await
            .unwrap();

        // Make sure we get a ping back
        let pong_response = ws_buffer.next().await.unwrap().unwrap();
        assert_eq!(pong_response, ws::Frame::Ping(Bytes::from_static(b"")));
    }

    #[actix_rt::test]
    async fn test_echo_socket_generic_binary() {
        let mut srv = test::start(|| {
            App::new().service(web::resource("/").to(
                |req: HttpRequest, stream: web::Payload| async move {
                    ws::start(EchoSocket::new(), &req, stream)
                },
            ))
        });

        let mut ws_buffer = srv.ws().await.unwrap();

        // Send generic bytes
        ws_buffer
            .send(ws::Message::Binary(Bytes::from_static(b"some bytes")))
            .await
            .unwrap();

        // Make sure we get the same bytes back
        let binary_response = ws_buffer.next().await.unwrap().unwrap();
        assert_eq!(
            binary_response,
            ws::Frame::Binary(Bytes::from_static(b"some bytes"))
        );
    }

    #[actix_rt::test]
    async fn test_echo_socket_special_binary() {
        let mut srv = test::start(|| {
            App::new().service(web::resource("/").to(
                |req: HttpRequest, stream: web::Payload| async move {
                    ws::start(EchoSocket::new(), &req, stream)
                },
            ))
        });

        let mut ws_buffer = srv.ws().await.unwrap();

        // Send the magic bytes
        ws_buffer
            .send(ws::Message::Binary(Bytes::from_static(b"U")))
            .await
            .unwrap();

        // Make sure we get the special response back
        let binary_response = ws_buffer.next().await.unwrap().unwrap();
        assert_eq!(binary_response, ws::Frame::Binary(Bytes::from_static(b"|")));
    }
}
