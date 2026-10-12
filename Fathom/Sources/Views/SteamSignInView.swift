import SwiftUI

/// Signing in to the user's own Steam account, and what is signed in.
struct SteamSignInView: View {
    @ObservedObject private var steam = SteamAccount.shared
    @State private var account = ""
    @State private var password = ""
    @State private var code = ""
    @FocusState private var focused: Field?

    enum Field { case account, password, code }

    var body: some View {
        Form {
            switch steam.phase {
            case .signedOut, .signingIn:
                credentials
            case .needsCode(let email, let hint):
                codeEntry(email: email, hint: hint)
            case .awaitingApproval:
                approval
            case .signedIn:
                signedIn
            }

            if let error = steam.error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.subheadline)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .navigationTitle("Steam")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var credentials: some View {
        Section {
            TextField("Account name", text: $account)
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($focused, equals: .account)
                .submitLabel(.next)
                .onSubmit { focused = .password }
            SecureField("Password", text: $password)
                .textContentType(.password)
                .focused($focused, equals: .password)
                .submitLabel(.go)
                .onSubmit(signIn)
            Button(action: signIn) {
                HStack {
                    Text("Sign In")
                    Spacer()
                    if steam.phase == .signingIn { ProgressView() }
                }
            }
            .disabled(account.isEmpty || password.isEmpty || steam.phase == .signingIn)
        } header: {
            Text("Your Steam account")
        } footer: {
            Text("Your password goes straight to Steam, encrypted with Steam's own key, and is never saved. Fathom keeps only the sign-in token Steam returns, in this device's Keychain.")
        }
    }

    private func codeEntry(email: Bool, hint: String) -> some View {
        Section {
            TextField(email ? "Code from your email" : "Code from the Steam app", text: $code)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .font(.technical(20, weight: .semibold))
                .focused($focused, equals: .code)
                .onAppear { focused = .code }
            Button("Continue") { Task { await steam.submitCode(code) } }
                .disabled(code.count < 5)
            Button("Cancel", role: .cancel) { steam.cancelSignIn() }
        } header: {
            Text("Steam Guard")
        } footer: {
            Text(email ? "Steam sent a code to \(hint.isEmpty ? "your email" : hint)." :
                    "Open the Steam app and enter the code it shows, or approve the sign-in there.")
        }
    }

    private var approval: some View {
        Section {
            HStack(spacing: 12) {
                ProgressView()
                Text("Approve the sign-in in the Steam app on your phone.")
            }
            Button("Cancel", role: .cancel) { steam.cancelSignIn() }
        } header: {
            Text("Steam Guard")
        }
    }

    private var signedIn: some View {
        Group {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: "person.crop.circle.fill")
                        .font(.largeTitle)
                        .foregroundStyle(Theme.accent)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(steam.accountName ?? "Signed in").font(.headline)
                        Text("\(steam.games.count) games in your library").font(.subheadline).foregroundStyle(.secondary)
                    }
                }
                Button {
                    Task { await steam.refreshLibrary() }
                } label: {
                    HStack {
                        Text("Refresh Library")
                        Spacer()
                        if steam.isLoadingLibrary { ProgressView() }
                    }
                }
            }
            Section {
                Button("Sign Out", role: .destructive) { steam.signOut() }
            } footer: {
                Text("Signing out removes the saved token and the cached library from this device.")
            }
        }
    }

    private func signIn() {
        guard !account.isEmpty, !password.isEmpty else { return }
        let password = self.password
        self.password = ""
        Task { await steam.signIn(account: account, password: password) }
    }
}
