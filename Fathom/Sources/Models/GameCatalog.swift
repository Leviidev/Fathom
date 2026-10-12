import CryptoKit
import SwiftUI
import UIKit

/// What the library shows about a game, from Steam's public store data: art, screenshots,
/// a description and the review summary. Fetched once per game and kept on disk, so the
/// library draws instantly and works offline after the first look.
struct GameInfo: Codable, Hashable {
    var appid: Int
    var name: String
    var description: String = ""
    var developer: String = ""
    var releaseDate: String = ""
    var genres: [String] = []
    var screenshots: [URL] = []
    var reviewSummary: String = ""
    var reviewPositive: Int = 0
    var reviewTotal: Int = 0
    var platforms: [String] = []

    var cover: URL { Self.art(appid, "library_600x900.jpg") }
    var hero: URL { Self.art(appid, "library_hero.jpg") }
    var logo: URL { Self.art(appid, "logo.png") }
    var header: URL { Self.art(appid, "header.jpg") }

    static func art(_ appid: Int, _ file: String) -> URL {
        URL(string: "https://cdn.cloudflare.steamstatic.com/steam/apps/\(appid)/\(file)")!
    }

    /// Positive share of reviews, 0...1, when there are any.
    var positiveShare: Double? { reviewTotal > 0 ? Double(reviewPositive) / Double(reviewTotal) : nil }
}

@MainActor
final class GameCatalog: ObservableObject {
    static let shared = GameCatalog()

    @Published private(set) var info: [Int: GameInfo] = [:]
    private var inFlight: Set<Int> = []
    private let directory: URL = {
        let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("GameInfo", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    /// Makes sure a game's details are loaded: from disk if they were fetched before, from
    /// Steam otherwise. Called from a view's task, never while it is drawing.
    func ensure(_ appid: Int, name: String) {
        guard info[appid] == nil else { return }
        let file = directory.appendingPathComponent("\(appid).json")
        if let data = try? Data(contentsOf: file), let cached = try? JSONDecoder().decode(GameInfo.self, from: data) {
            info[appid] = cached
            return
        }
        load(appid, name: name)
    }

    private func load(_ appid: Int, name: String) {
        guard !inFlight.contains(appid) else { return }
        inFlight.insert(appid)
        Task {
            defer { inFlight.remove(appid) }
            var game = GameInfo(appid: appid, name: name)
            if let store = await Self.json("https://store.steampowered.com/api/appdetails?appids=\(appid)&l=en"),
               let entry = store["\(appid)"] as? [String: Any], (entry["success"] as? Bool) == true,
               let data = entry["data"] as? [String: Any] {
                game.name = (data["name"] as? String) ?? name
                game.description = Self.plain((data["short_description"] as? String) ?? "")
                game.developer = ((data["developers"] as? [String]) ?? []).joined(separator: ", ")
                game.releaseDate = ((data["release_date"] as? [String: Any])?["date"] as? String) ?? ""
                game.genres = ((data["genres"] as? [[String: Any]]) ?? []).compactMap { $0["description"] as? String }
                game.screenshots = ((data["screenshots"] as? [[String: Any]]) ?? []).prefix(12)
                    .compactMap { ($0["path_full"] as? String).flatMap(URL.init(string:)) }
                if let platforms = data["platforms"] as? [String: Bool] {
                    game.platforms = ["windows", "mac", "linux"].filter { platforms[$0] == true }
                }
            }
            if let reviews = await Self.json("https://store.steampowered.com/appreviews/\(appid)?json=1&language=all&purchase_type=all&num_per_page=0"),
               let summary = reviews["query_summary"] as? [String: Any] {
                game.reviewSummary = (summary["review_score_desc"] as? String) ?? ""
                game.reviewPositive = (summary["total_positive"] as? Int) ?? 0
                game.reviewTotal = (summary["total_reviews"] as? Int) ?? 0
            }
            info[appid] = game
            if let data = try? JSONEncoder().encode(game) {
                try? data.write(to: directory.appendingPathComponent("\(appid).json"), options: .atomic)
            }
        }
    }

    /// The Steam app a folder name most likely is, from the store's own search.
    static func match(name: String) async -> (appid: Int, name: String)? {
        let term = name.replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "-", with: " ")
        guard let encoded = term.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let reply = await json("https://store.steampowered.com/api/storesearch/?term=\(encoded)&cc=us&l=en"),
              let first = (reply["items"] as? [[String: Any]])?.first,
              let id = first["id"] as? Int else { return nil }
        return (id, (first["name"] as? String) ?? name)
    }

    private static func json(_ address: String) async -> [String: Any]? {
        guard let url = URL(string: address),
              let (data, _) = try? await URLSession.shared.data(from: url) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private static func plain(_ html: String) -> String {
        html.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
            .replacingOccurrences(of: "&quot;", with: "\"").replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&#39;", with: "'")
    }
}

/// Images from the network, kept in memory and on disk. Library grids scroll through
/// hundreds of covers, so nothing is fetched twice and nothing is decoded on the main thread.
final class ImageStore {
    static let shared = ImageStore()
    private let memory = NSCache<NSURL, UIImage>()
    private let directory: URL = {
        let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Images", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    init() { memory.countLimit = 300 }

    func cached(_ url: URL) -> UIImage? { memory.object(forKey: url as NSURL) }

    func image(_ url: URL) async -> UIImage? {
        if let hit = cached(url) { return hit }
        let name = SHA256.hash(data: Data(url.absoluteString.utf8)).prefix(12).map { String(format: "%02x", $0) }.joined()
        let file = directory.appendingPathComponent(name)
        let data: Data
        if let disk = try? Data(contentsOf: file) {
            data = disk
        } else {
            guard let (fetched, response) = try? await URLSession.shared.data(from: url),
                  (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
            data = fetched
            try? data.write(to: file, options: .atomic)
        }
        guard let image = await Task.detached(priority: .utility, operation: { UIImage(data: data)?.preparingForDisplay() }).value else { return nil }
        memory.setObject(image, forKey: url as NSURL)
        return image
    }
}

/// A remote image with a placeholder, through `ImageStore`.
struct RemoteImage<Placeholder: View>: View {
    let url: URL?
    var contentMode: ContentMode = .fill
    @ViewBuilder var placeholder: () -> Placeholder
    @State private var image: UIImage?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().aspectRatio(contentMode: contentMode)
            } else {
                placeholder()
            }
        }
        .task(id: url) {
            guard let url else { return }
            image = ImageStore.shared.cached(url)
            if image == nil { image = await ImageStore.shared.image(url) }
        }
    }
}
