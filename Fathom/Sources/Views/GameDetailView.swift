import SwiftUI

/// One game: its art, what Steam says about it, and the way to play it.
struct GameDetailView: View {
    enum Source: Hashable {
        case steam(SteamAccount.OwnedGame)
        case imported(ImportedGame)
    }

    let source: Source
    @ObservedObject private var catalog = GameCatalog.shared
    @State private var viewingScreenshot: URL?

    private var appid: Int? {
        switch source {
        case .steam(let game): return game.appid
        case .imported(let game): return game.appid
        }
    }

    private var title: String {
        switch source {
        case .steam(let game): return game.name
        case .imported(let game): return game.name
        }
    }

    private var info: GameInfo? {
        appid.flatMap { catalog.info[$0] }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                hero
                VStack(alignment: .leading, spacing: 20) {
                    play
                    if let info, !info.reviewSummary.isEmpty { reviews(info) }
                    if let info, !info.description.isEmpty {
                        Text(info.description).font(.body).foregroundStyle(.primary.opacity(0.9))
                    }
                    if let info, !info.screenshots.isEmpty { screenshots(info) }
                    details
                }
                .padding(.horizontal, 16)
            }
            .padding(.bottom, 32)
        }
        .background(Theme.background)
        .ignoresSafeArea(edges: .top)
        .navigationBarTitleDisplayMode(.inline)
        .task { if let appid { catalog.ensure(appid, name: title) } }
        .fullScreenCover(item: $viewingScreenshot) { url in
            ZStack(alignment: .topTrailing) {
                Color.black.ignoresSafeArea()
                RemoteImage(url: url, contentMode: .fit) { ProgressView().tint(.white) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                Button { viewingScreenshot = nil } label: {
                    Image(systemName: "xmark.circle.fill").font(.title).foregroundStyle(.white.opacity(0.85))
                }
                .padding()
            }
        }
    }

    // MARK: - Pieces

    private var hero: some View {
        ZStack(alignment: .bottomLeading) {
            Group {
                if let appid {
                    RemoteImage(url: GameInfo.art(appid, "library_hero.jpg")) {
                        RemoteImage(url: GameInfo.art(appid, "header.jpg")) { Theme.surfaceRaised }
                    }
                } else {
                    Theme.surfaceRaised
                }
            }
            .frame(height: 260)
            .frame(maxWidth: .infinity)
            .clipped()
            // A plain dark band under the logo so it reads on any art -- solid, not a colour wash.
            .overlay(alignment: .bottom) { Color.black.opacity(0.35).frame(height: 90) }

            Group {
                if let appid {
                    RemoteImage(url: GameInfo.art(appid, "logo.png"), contentMode: .fit) { titleText }
                } else {
                    titleText
                }
            }
            .frame(maxWidth: 260, maxHeight: 80, alignment: .bottomLeading)
            .padding(16)
        }
    }

    private var titleText: some View {
        Text(title).font(.title.weight(.bold)).foregroundStyle(.white).lineLimit(2)
    }

    @ViewBuilder
    private var play: some View {
        switch source {
        case .steam(let game):
            let installed = SteamCmd.isGameInstalled(game.appid)
            NavigationLink { DownloadView(appid: game.appid, name: game.name) } label: {
                playLabel(installed ? "Installed \u{00B7} Update" : "Download", systemImage: installed ? "checkmark.circle" : "arrow.down.to.line")
            }
            .buttonStyle(.plain)
            if installed {
                Text("\(formatBytes(SteamCmd.installedSize(game.appid))) in Files \u{203A} Fathom \u{203A} GuestRoot \u{203A} root \u{203A} games \u{203A} \(game.appid). Fathom runs Windows games through Wine; playing them here arrives in an upcoming build.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Downloads with your Steam account through steamcmd, into the Files app.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if info?.platforms.contains("linux") == true && GuestRootfs.hasSteam {
                NavigationLink { SteamView() } label: { playLabel("Play in Steam", systemImage: "play.fill") }
                    .buttonStyle(.plain)
            }
        case .imported(let game):
            playLabel("Windows games are coming", systemImage: "hourglass").opacity(0.55)
            Text("Starts \(game.executable). Fathom runs Windows games through Wine; that arrives in an upcoming build.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func playLabel(_ text: String, systemImage: String) -> some View {
        Label(text, systemImage: systemImage)
            .font(.headline)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .foregroundStyle(.white)
            .background(Theme.accent, in: RoundedRectangle(cornerRadius: Theme.cardCorner))
    }

    private func reviews(_ info: GameInfo) -> some View {
        HStack(spacing: 12) {
            Image(systemName: (info.positiveShare ?? 0) >= 0.7 ? "hand.thumbsup.fill" : "hand.thumbsdown.fill")
                .foregroundStyle((info.positiveShare ?? 0) >= 0.7 ? Theme.accent : .orange)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(info.reviewSummary).font(.subheadline.weight(.semibold))
                if let share = info.positiveShare {
                    Text("\(Int(share * 100))% of \(info.reviewTotal.formatted()) reviews are positive")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(14)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.cardCorner))
    }

    private func screenshots(_ info: GameInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Screenshots").font(.headline)
            ScrollView(.horizontal, showsIndicators: false) {
                LazyHStack(spacing: 10) {
                    ForEach(info.screenshots, id: \.self) { url in
                        Button { viewingScreenshot = url } label: {
                            RemoteImage(url: url) { Theme.surfaceRaised }
                                .frame(width: 260, height: 146)
                                .clipShape(RoundedRectangle(cornerRadius: Theme.tileCorner))
                        }
                    }
                }
            }
            .padding(.horizontal, -16)
            .contentMargins(.horizontal, 16, for: .scrollContent)
        }
    }

    private var details: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Details").font(.subheadline.weight(.semibold))
                if let info, !info.developer.isEmpty { DetailRow(label: "Developer", value: info.developer, mono: false) }
                if let info, !info.releaseDate.isEmpty { DetailRow(label: "Released", value: info.releaseDate, mono: false) }
                if let info, !info.genres.isEmpty { DetailRow(label: "Genres", value: info.genres.prefix(3).joined(separator: ", "), mono: false) }
                if let info, !info.platforms.isEmpty {
                    DetailRow(label: "Platforms", value: info.platforms.map { $0 == "mac" ? "macOS" : $0.capitalized }.joined(separator: ", "), mono: false)
                }
                switch source {
                case .steam(let game):
                    DetailRow(label: "Played", value: game.playtimeMinutes < 60 ? "\(game.playtimeMinutes) min" : "\(game.playtimeMinutes / 60) h", mono: false)
                    DetailRow(label: "App ID", value: "\(game.appid)")
                case .imported(let game):
                    DetailRow(label: "Executable", value: game.executable)
                    DetailRow(label: "Added", value: game.addedAt.formatted(date: .abbreviated, time: .omitted), mono: false)
                }
            }
        }
    }
}

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}
