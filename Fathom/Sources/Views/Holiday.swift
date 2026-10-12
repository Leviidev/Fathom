import SwiftUI

/// Christmas decorations, the same as Husk's: snow falling over the tabs, snow resting on cards, and a lit tree
/// in the Library header. Purely decoration -- nothing here takes touches -- and one switch in Settings turns it off.
enum Holiday {
    static let key = "holiday.decorations"
}

/// Snow falling over the whole screen. Each flake is a fixed function of time, so there is no state to keep
/// and nothing to simulate; the canvas just draws where every flake is now.
struct Snowfall: View {
    @Environment(\.colorScheme) private var scheme
    private let flakes: [Flake] = (0..<70).map { Flake(seed: $0) }

    struct Flake {
        let x, speed, size, sway, phase, alpha: Double
        init(seed: Int) {
            // a small deterministic hash per flake, so the snow looks the same on every launch
            func r(_ k: Int) -> Double { let v = sin(Double(seed * 92821 + k * 68917)) * 43758.5453; return v - floor(v) }
            x = r(1); speed = 0.035 + r(2) * 0.06; size = 1.6 + r(3) * 3.2; sway = 6 + r(4) * 18; phase = r(5) * 6.28; alpha = 0.45 + r(6) * 0.5
        }
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30)) { tl in
            Canvas { ctx, size in
                let t = tl.date.timeIntervalSinceReferenceDate
                let tint = scheme == .dark ? Color.white : Color(red: 0.66, green: 0.76, blue: 0.88)
                for f in flakes {
                    let fall = (t * f.speed + f.phase).truncatingRemainder(dividingBy: 1.0)
                    let y = fall * (size.height + 20) - 10
                    let x = f.x * size.width + sin(t * 0.6 + f.phase) * f.sway
                    let rect = CGRect(x: x, y: y, width: f.size, height: f.size)
                    ctx.fill(Path(ellipseIn: rect), with: .color(tint.opacity(f.alpha)))
                }
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// The lumpy top edge of a layer of snow: flat on top, scalloped underneath.
private struct SnowCapShape: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        let bumps = max(3, Int(r.width / 22))
        let w = r.width / CGFloat(bumps)
        p.move(to: CGPoint(x: r.minX, y: r.minY + r.height * 0.35))
        p.addQuadCurve(to: CGPoint(x: r.minX + r.height * 0.6, y: r.minY), control: CGPoint(x: r.minX, y: r.minY))
        p.addLine(to: CGPoint(x: r.maxX - r.height * 0.6, y: r.minY))
        p.addQuadCurve(to: CGPoint(x: r.maxX, y: r.minY + r.height * 0.35), control: CGPoint(x: r.maxX, y: r.minY))
        for i in (0..<bumps).reversed() {
            let x0 = r.minX + CGFloat(i) * w, deep = (i % 2 == 0) ? 1.0 : 0.72
            p.addQuadCurve(to: CGPoint(x: x0, y: r.minY + r.height * 0.35),
                           control: CGPoint(x: x0 + w / 2, y: r.minY + r.height * deep * 1.25))
        }
        p.closeSubpath()
        return p
    }
}

private struct SnowCap: ViewModifier {
    @AppStorage(Holiday.key) private var on = true
    var height: CGFloat
    func body(content: Content) -> some View {
        content.overlay(alignment: .top) {
            if on {
                SnowCapShape()
                    .fill(Color.white)
                    .frame(height: height)
                    .padding(.horizontal, -1)
                    .offset(y: -height * 0.3)
                    .shadow(color: .black.opacity(0.14), radius: 1.2, y: 0.8)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
        }
    }
}

extension View {
    /// Snow resting on the top edge of a card or icon (when decorations are on).
    func snowCap(height: CGFloat = 9) -> some View { modifier(SnowCap(height: height)) }
}

/// A small tree with a star and lights that twinkle, for the Library header.
struct ChristmasTree: View {
    var size: CGFloat = 30
    private let lights: [(CGFloat, CGFloat, Color)] = [
        (0.47, 0.34, .red), (0.58, 0.44, .yellow), (0.38, 0.52, .blue), (0.62, 0.60, .orange),
        (0.44, 0.66, .pink), (0.30, 0.76, .yellow), (0.55, 0.78, .red), (0.70, 0.80, .blue), (0.40, 0.86, .orange),
    ]
    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.45)) { tl in
            let tick = Int(tl.date.timeIntervalSinceReferenceDate / 0.45)
            ZStack {
                Rectangle().fill(Color(red: 0.45, green: 0.28, blue: 0.16))
                    .frame(width: size * 0.14, height: size * 0.14).offset(y: size * 0.44)
                tier(width: 1.0, top: 0.42, bottom: 0.93)
                tier(width: 0.78, top: 0.24, bottom: 0.68)
                tier(width: 0.56, top: 0.07, bottom: 0.45)
                Image(systemName: "star.fill").font(.system(size: size * 0.24)).foregroundStyle(.yellow)
                    .offset(y: -size * 0.44)
                ForEach(lights.indices, id: \.self) { i in
                    let (x, y, c) = lights[i]
                    let lit = (i + tick) % 3 != 0
                    Circle().fill(c.opacity(lit ? 1 : 0.25))
                        .frame(width: size * 0.09, height: size * 0.09)
                        .shadow(color: lit ? c : .clear, radius: size * 0.08)
                        .position(x: x * size, y: y * size)
                }
            }
            .frame(width: size, height: size)
        }
        .accessibilityHidden(true)
    }

    private func tier(width: CGFloat, top: CGFloat, bottom: CGFloat) -> some View {
        Path { p in
            p.move(to: CGPoint(x: size / 2, y: top * size))
            p.addLine(to: CGPoint(x: size / 2 + width * size / 2, y: bottom * size))
            p.addLine(to: CGPoint(x: size / 2 - width * size / 2, y: bottom * size))
            p.closeSubpath()
        }
        .fill(Color(red: 0.13, green: 0.55, blue: 0.27))
        .frame(width: size, height: size)
    }
}
