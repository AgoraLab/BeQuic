#include "net/tools/quic/be_quic_fake_proof_verifier.h"
#include "absl/strings/string_view.h"

namespace quic {

quic::QuicAsyncStatus BeQuicFakeProofVerifier::VerifyProof(
    const std::string& hostname,
    const uint16_t port,
    const std::string& server_config,
    quic::QuicTransportVersion quic_version,
    absl::string_view chlo_hash,
    const std::vector<std::string>& certs,
    const std::string& cert_sct,
    const std::string& signature,
    const quic::ProofVerifyContext* context,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* details,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
    return quic::QUIC_SUCCESS;
}

quic::QuicAsyncStatus BeQuicFakeProofVerifier::VerifyCertChain(
            const std::string& hostname,
            const uint16_t port,
            const std::vector<std::string>& certs,
            const std::string& ocsp_response,
            const std::string& cert_sct,
            const ProofVerifyContext* context,
            std::string* error_details,
            std::unique_ptr<ProofVerifyDetails>* details,
            uint8_t* out_alert,
            std::unique_ptr<ProofVerifierCallback> callback) {
    return quic::QUIC_SUCCESS;
}

std::unique_ptr<quic::ProofVerifyContext> BeQuicFakeProofVerifier::CreateDefaultContext() {
    return nullptr;
}

} // namespace quic
