// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.

//! Compile the agreed public API as an external caller. These functions are not
//! executed while the API is a skeleton; their bodies keep signature changes
//! visible without claiming the documented runtime contracts are implemented.

#![allow(dead_code)]

use darkbio_crypto::xdsa;
use darkbio_wire::protocol::{
    self, Closer, DeviceInfoRequest, DeviceInfoResponse, Error, Message, Pending, RemoteError,
    Requester, Responder, Server, Session, WritePending,
};
use darkbio_wire::transport::{Attester, Read, Stream, Verifier, Write};
use std::time::Instant;

fn connect<R, W, V>(stream: Stream<R, W>, verifier: &V) -> Result<(Session, V::Info), Error>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    V: Verifier,
{
    protocol::connect(stream, verifier)
}

fn server<R, W, A>(stream: Stream<R, W>, signer: xdsa::SecretKey, attester: A) -> Server
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
    A: Attester + Send + 'static,
{
    Server::new(stream, signer, attester)
}

fn accept(server: &mut Server) -> Result<Session, Error> {
    server.accept()
}

fn pipeline(session: &Session, deadline: Instant) -> Result<(), Error> {
    let requester: Requester = session.requester();
    let first: Pending = requester.request(DeviceInfoRequest {}, deadline)?;
    let second = requester.request(DeviceInfoRequest {}, deadline)?;

    // Observation can be abandoned without selecting a response type.
    drop(requester.request(DeviceInfoRequest {}, deadline)?);

    // Caller-selected typing, by annotation or by explicit generic argument.
    let _: DeviceInfoResponse = second.wait()?;
    let _ = first.wait::<DeviceInfoResponse>()?;

    // Callers may also request the message enum to match it themselves.
    let _: Message = requester.request(DeviceInfoRequest {}, deadline)?.wait()?;
    Ok(())
}

fn receive_on_host(session: &mut Session, deadline: Instant) -> Result<(), Error> {
    let (request, responder): (Message, Responder) = session.recv()?;
    let _ = request;
    responder
        .reply(
            Err(RemoteError {
                code: 1,
                msg: "refused".into(),
            }),
            deadline,
        )?
        .wait()
}

fn receive_on_server(session: &mut Session, deadline: Instant) -> Result<(), Error> {
    let (request, responder): (Message, Responder) = session.recv()?;
    match request {
        Message::DeviceInfoRequest(_) => {
            let written: WritePending =
                responder.reply(Ok(DeviceInfoResponse::default().into()), deadline)?;
            written.wait()?;
        }
        Message::Develop(bytes) => {
            // Opaque development traffic is supported in both directions.
            let requester = session.requester();
            std::thread::spawn(move || -> Result<(), Error> {
                let answer: Vec<u8> = requester.request(bytes, deadline)?.wait()?;
                drop(responder.reply(Ok(answer.into()), deadline)?);
                Ok(())
            });
        }
        _ => drop(responder), // Schedules an abandonment error in the real implementation.
    }
    Ok(())
}

fn cross_thread_close(session: &Session, server: &Server) {
    let session_closer: Closer = session.closer();
    let endpoint_closer: Closer = server.closer();
    let session_copy = session_closer.clone();
    let endpoint_copy = endpoint_closer.clone();
    std::thread::spawn(move || session_copy.close());
    std::thread::spawn(move || endpoint_copy.close());
    session.close();
    server.close();
}

// These bounds are part of how applications hand owners and capabilities to jobs.
#[test]
fn thread_capabilities() {
    fn movable<T: Send + 'static>() {}
    fn shared<T: Clone + Send + Sync + 'static>() {}
    movable::<Server>();
    movable::<Session>();
    movable::<Responder>();
    movable::<Pending>();
    movable::<WritePending>();
    shared::<Requester>();
    shared::<Closer>();
}

// Empty protobuf messages decode each other's bytes successfully. Extraction must
// still reject a different envelope variant; decoding as the requested type is not
// a valid response-type check. This tests the conversions that already work.
#[test]
fn response_extraction_checks_the_variant() {
    use prost::Message as _;

    let other = protocol::OnboardingResponse {};
    assert!(DeviceInfoResponse::decode(other.encode_to_vec().as_slice()).is_ok());
    let message: Message = other.into();
    assert!(matches!(
        DeviceInfoResponse::try_from(message),
        Err(Error::UnexpectedResponse {
            expected: "DeviceInfoResponse",
            received: "OnboardingResponse",
        })
    ));

    // These bodies have the same field name and tag in opposite wire envelopes,
    // but must remain distinct variants in the common public message enum.
    let message: Message = DeviceInfoRequest {}.into();
    assert!(matches!(
        DeviceInfoResponse::try_from(message),
        Err(Error::UnexpectedResponse {
            expected: "DeviceInfoResponse",
            received: "DeviceInfoRequest",
        })
    ));

    let response = DeviceInfoResponse {
        version_id: 7,
        ..Default::default()
    };
    let message: Message = response.clone().into();
    assert_eq!(DeviceInfoResponse::try_from(message).unwrap(), response);

    let message: Message = vec![1, 2, 3].into();
    assert_eq!(Vec::<u8>::try_from(message).unwrap(), vec![1, 2, 3]);
}
