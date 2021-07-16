#include "net/tools/quic/be_quic_spdy_client_session.h"
#include "net/tools/quic/be_quic_spdy_client_stream.h"

namespace quic {

BeQuicSpdyClientSession::BeQuicSpdyClientSession(
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    QuicClientPushPromiseIndex* push_promise_index)
    : QuicSpdyClientSession(
        config,
        supported_versions,
        connection,
        server_id,
        crypto_config,
        push_promise_index) {

}

BeQuicSpdyClientSession::~BeQuicSpdyClientSession() {

}

std::unique_ptr<QuicSpdyClientStream> BeQuicSpdyClientSession::CreateClientStream() {
    std::unique_ptr<BeQuicSpdyClientStream> stream = std::make_unique<BeQuicSpdyClientStream>(
        GetNextOutgoingBidirectionalStreamId(), this, BIDIRECTIONAL);
    stream.get()->set_delegate(delegate_);

    std::shared_ptr<net::BeQuicSpdyDataDelegate> delegate = delegate_.lock();
    if (delegate != NULL) {
        delegate->on_stream_created(stream.get());
    }

    return stream;
}

void BeQuicSpdyClientSession::OnConnectionClosed(const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
    LOG(INFO) << "Session " << connection_id().ToString() << " closed, error:" << quic::QuicErrorCodeToString(frame.quic_error_code)
              << ", details:" << frame.error_details << ", source:"
              << static_cast<std::underlying_type<ConnectionCloseSource>::type>(source);

    quic::QuicSession::OnConnectionClosed(frame, source);
}

bool BeQuicSpdyClientSession::ShouldKeepConnectionAlive() const {
    return QuicSpdySession::ShouldKeepConnectionAlive();
}

}  // namespace quic
