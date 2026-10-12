import Foundation
import Security

/// The user's own Steam account: signing in, and the library it owns.
///
/// Sign-in goes through Steam's public web authentication service -- the same calls the
/// steamcommunity.com login page makes -- so the password is RSA-encrypted with Steam's
/// key before it leaves the device and is never stored. What is kept, in the Keychain, is
/// the refresh token Steam hands back, which is what "stay signed in" means on the web.
@MainActor
final class SteamAccount: ObservableObject {
    static let shared = SteamAccount()

    struct OwnedGame: Codable, Identifiable, Hashable {
        let appid: Int
        let name: String
        let playtimeMinutes: Int
        var id: Int { appid }
    }

    enum Phase: Equatable {
        case signedOut
        case signingIn
        /// Steam wants a code: from email, or from the authenticator in the Steam app.
        case needsCode(email: Bool, hint: String)
        /// Steam wants the sign-in approved in the Steam mobile app; this polls until it is.
        case awaitingApproval
        case signedIn
    }

    @Published private(set) var phase: Phase = .signedOut
    @Published private(set) var accountName: String?
    @Published private(set) var games: [OwnedGame] = []
    @Published private(set) var isLoadingLibrary = false
    @Published var error: String?

    private var steamID: String?
    private var accessToken: String?
    private var pending: (clientID: String, requestID: String, steamID: String, interval: Double)?
    private var pollTask: Task<Void, Never>?

    private static let api = URL(string: "https://api.steampowered.com")!
    private static let keychainService = "Fathom.Steam"

    private var cacheURL: URL {
        ProgramLibrary.documentsDirectory.appendingPathComponent(".steam-library.json")
    }

    private init() {
        if let name = Keychain.read(Self.keychainService, "account"),
           let id = Keychain.read(Self.keychainService, "steamid"),
           Keychain.read(Self.keychainService, "refresh") != nil {
            accountName = name
            steamID = id
            phase = .signedIn
            if let data = try? Data(contentsOf: cacheURL),
               let cached = try? JSONDecoder().decode([OwnedGame].self, from: data) {
                games = cached
            }
            Task { await refreshLibrary() }
        }
    }

    // MARK: - Signing in

    func signIn(account: String, password: String) async {
        error = nil
        phase = .signingIn
        do {
            let key = try await call("IAuthenticationService/GetPasswordRSAPublicKey/v1", get: ["account_name": account])
            guard let modulus = key["publickey_mod"] as? String, let exponent = key["publickey_exp"] as? String,
                  let timestamp = key["timestamp"] as? String else { throw SteamError("Steam did not return a sign-in key.") }
            let encrypted = try Self.encrypt(password, modulusHex: modulus, exponentHex: exponent)

            let session = try await call("IAuthenticationService/BeginAuthSessionViaCredentials/v1", post: [
                "account_name": account,
                "encrypted_password": encrypted,
                "encryption_timestamp": timestamp,
                "remember_login": "true",
                "platform_type": "2", // web browser
                "persistence": "1",   // persistent session
                "website_id": "Community",
            ])
            guard let clientID = Self.string(session["client_id"]), let requestID = session["request_id"] as? String,
                  let steamID = Self.string(session["steamid"]) else {
                throw SteamError("Steam did not accept that account name and password.")
            }
            let interval = (session["interval"] as? Double) ?? 5
            pending = (clientID, requestID, steamID, interval)
            accountName = account

            // What Steam will accept as the second factor, if anything.
            let confirmations = (session["allowed_confirmations"] as? [[String: Any]]) ?? []
            let types = confirmations.compactMap { $0["confirmation_type"] as? Int }
            let hint = confirmations.first.flatMap { $0["associated_message"] as? String } ?? ""
            if types.contains(1) || types.isEmpty {
                startPolling()
            } else if types.contains(3) {
                phase = .needsCode(email: false, hint: hint)
                if types.contains(4) { startPolling() } // the app can approve it as well
            } else if types.contains(2) {
                phase = .needsCode(email: true, hint: hint)
            } else if types.contains(4) {
                phase = .awaitingApproval
                startPolling()
            } else {
                throw SteamError("Steam asked for a kind of confirmation Fathom does not support yet.")
            }
        } catch {
            self.error = error.localizedDescription
            phase = .signedOut
        }
    }

    func submitCode(_ code: String) async {
        guard let pending, case .needsCode(let email, _) = phase else { return }
        error = nil
        do {
            _ = try await call("IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1", post: [
                "client_id": pending.clientID,
                "steamid": pending.steamID,
                "code": code.trimmingCharacters(in: .whitespaces).uppercased(),
                "code_type": email ? "2" : "3",
            ])
            startPolling()
        } catch {
            self.error = "That code was not accepted. \(error.localizedDescription)"
        }
    }

    func cancelSignIn() {
        pollTask?.cancel()
        pending = nil
        phase = .signedOut
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            guard let self else { return }
            for _ in 0..<60 {
                guard let pending = self.pending, !Task.isCancelled else { return }
                do {
                    let status = try await self.call("IAuthenticationService/PollAuthSessionStatus/v1", post: [
                        "client_id": pending.clientID, "request_id": pending.requestID,
                    ])
                    if let refresh = status["refresh_token"] as? String, !refresh.isEmpty {
                        self.finishSignIn(refresh: refresh, access: status["access_token"] as? String,
                                          steamID: pending.steamID, name: (status["account_name"] as? String) ?? self.accountName ?? "")
                        return
                    }
                } catch {
                    self.error = error.localizedDescription
                    self.phase = .signedOut
                    return
                }
                try? await Task.sleep(for: .seconds(pending.interval))
            }
            self.error = "Sign-in timed out. Try again."
            self.phase = .signedOut
        }
    }

    private func finishSignIn(refresh: String, access: String?, steamID: String, name: String) {
        Keychain.write(Self.keychainService, "refresh", refresh)
        Keychain.write(Self.keychainService, "steamid", steamID)
        Keychain.write(Self.keychainService, "account", name)
        self.steamID = steamID
        accessToken = access
        accountName = name
        pending = nil
        phase = .signedIn
        log("signed in to Steam as \(name)")
        Task { await refreshLibrary() }
    }

    func signOut() {
        pollTask?.cancel()
        for item in ["refresh", "steamid", "account"] { Keychain.delete(Self.keychainService, item) }
        try? FileManager.default.removeItem(at: cacheURL)
        accessToken = nil
        steamID = nil
        accountName = nil
        games = []
        phase = .signedOut
    }

    // MARK: - Library

    func refreshLibrary() async {
        guard let steamID, phase == .signedIn else { return }
        isLoadingLibrary = true
        defer { isLoadingLibrary = false }
        do {
            let token = try await validAccessToken()
            let owned = try await call("IPlayerService/GetOwnedGames/v1", get: [
                "access_token": token, "steamid": steamID,
                "include_appinfo": "true", "include_played_free_games": "true",
            ])
            let list = (owned["games"] as? [[String: Any]]) ?? []
            games = list.compactMap { entry in
                guard let id = entry["appid"] as? Int, let name = entry["name"] as? String else { return nil }
                return OwnedGame(appid: id, name: name, playtimeMinutes: (entry["playtime_forever"] as? Int) ?? 0)
            }
            .sorted { $0.playtimeMinutes == $1.playtimeMinutes ? $0.name < $1.name : $0.playtimeMinutes > $1.playtimeMinutes }
            if let data = try? JSONEncoder().encode(games) { try? data.write(to: cacheURL, options: .atomic) }
            log("Steam library: \(games.count) games")
        } catch {
            self.error = "Could not load your Steam library: \(error.localizedDescription)"
        }
    }

    /// An access token, minted from the stored refresh token when there is none yet.
    private func validAccessToken() async throws -> String {
        if let accessToken { return accessToken }
        guard let refresh = Keychain.read(Self.keychainService, "refresh"), let steamID else {
            throw SteamError("Not signed in.")
        }
        let reply = try await call("IAuthenticationService/GenerateAccessTokenForApp/v1", post: [
            "refresh_token": refresh, "steamid": steamID,
        ])
        guard let token = reply["access_token"] as? String else {
            signOut()
            throw SteamError("Your Steam session has expired. Sign in again.")
        }
        accessToken = token
        return token
    }

    // MARK: - Plumbing

    private func call(_ method: String, get query: [String: String]? = nil, post form: [String: String]? = nil) async throws -> [String: Any] {
        var components = URLComponents(url: Self.api.appendingPathComponent(method), resolvingAgainstBaseURL: false)!
        if let query { components.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) } }
        var request = URLRequest(url: components.url!)
        request.timeoutInterval = 20
        if let form {
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            request.httpBody = form.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "")" }
                .joined(separator: "&").data(using: .utf8)
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse {
            if let result = http.value(forHTTPHeaderField: "x-eresult"), result != "1" {
                throw SteamError(Self.describe(result: result))
            }
            guard (200..<300).contains(http.statusCode) else { throw SteamError("Steam answered HTTP \(http.statusCode).") }
        }
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return (json?["response"] as? [String: Any]) ?? [:]
    }

    private static func describe(result: String) -> String {
        switch result {
        case "5": return "Incorrect account name or password."
        case "65", "88": return "Incorrect Steam Guard code."
        case "84": return "Too many attempts. Wait a while and try again."
        case "9": return "Steam could not find that account."
        default: return "Steam refused the request (EResult \(result))."
        }
    }

    private static func string(_ value: Any?) -> String? {
        if let s = value as? String { return s }
        if let n = value as? NSNumber { return n.stringValue }
        return nil
    }

    /// RSA PKCS#1 v1.5 with Steam's per-account key, base64 -- what Steam's own login page sends.
    private static func encrypt(_ password: String, modulusHex: String, exponentHex: String) throws -> String {
        func bytes(_ hex: String) -> [UInt8] {
            var out: [UInt8] = []
            var chars = Array(hex)
            if chars.count % 2 == 1 { chars.insert("0", at: 0) }
            for i in stride(from: 0, to: chars.count, by: 2) { out.append(UInt8(String(chars[i...i + 1]), radix: 16) ?? 0) }
            return out
        }
        func der(length: Int) -> [UInt8] {
            if length < 0x80 { return [UInt8(length)] }
            var len = length, digits: [UInt8] = []
            while len > 0 { digits.insert(UInt8(len & 0xff), at: 0); len >>= 8 }
            return [0x80 | UInt8(digits.count)] + digits
        }
        func integer(_ value: [UInt8]) -> [UInt8] {
            var v = value
            while v.count > 1 && v[0] == 0 { v.removeFirst() }
            if let first = v.first, first & 0x80 != 0 { v.insert(0, at: 0) }
            return [0x02] + der(length: v.count) + v
        }
        let body = integer(bytes(modulusHex)) + integer(bytes(exponentHex))
        let publicKey = Data([0x30] + der(length: body.count) + body)
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        var failure: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(publicKey as CFData, attributes as CFDictionary, &failure),
              let cipher = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, Data(password.utf8) as CFData, &failure) else {
            throw SteamError("Could not encrypt the password for Steam.")
        }
        return (cipher as Data).base64EncodedString()
    }
}

struct SteamError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// Generic-password Keychain items, this device only.
enum Keychain {
    static func write(_ service: String, _ account: String, _ value: String) {
        delete(service, account)
        let item: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account,
            kSecValueData: Data(value.utf8), kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(item as CFDictionary, nil)
    }

    static func read(_ service: String, _ account: String) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account,
            kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(_ service: String, _ account: String) {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account]
        SecItemDelete(query as CFDictionary)
    }
}
