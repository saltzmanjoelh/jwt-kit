import CJWTKitCrypto
import struct Foundation.Data

internal struct RSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: RSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }
        var signatureLength: UInt32 = 0
        var signature = [UInt8](
            repeating: 0,
            count: Int(RSA_size(convert(key.c)))
        )

        let digest = try self.digest(plaintext)
        guard RSA_sign(
            EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            convert(self.key.c)
        ) == 1 else {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure)
        }

        return .init(signature[0..<numericCast(signatureLength)])
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = signature.copyBytes()
        return RSA_verify(
            EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            convert(self.key.c)
        ) == 1
    }
}