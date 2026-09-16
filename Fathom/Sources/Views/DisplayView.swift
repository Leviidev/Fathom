import SwiftUI

/// The guest's screen.
///
/// Shows whatever the X server has drawn, letterboxed into whatever space it is given and
/// never scaled past its own resolution's aspect. Until something draws, it says so rather
/// than showing an empty black rectangle that looks like a failure.
struct DisplayView: View {
    @ObservedObject var display: GuestDisplay
    /// Where a tap or drag in view coordinates lands on the guest's screen.
    var onPoint: ((CGPoint) -> Void)?
    var onClick: ((CGPoint, Bool) -> Void)?

    var body: some View {
        GeometryReader { geometry in
            let rect = fittedRect(in: geometry.size)
            ZStack {
                Color.black
                if let frame = display.frame {
                    Image(decorative: frame, scale: 1, orientation: .up)
                        .resizable()
                        .interpolation(.low)
                        .frame(width: rect.width, height: rect.height)
                        .position(x: rect.midX, y: rect.midY)
                } else {
                    waiting
                }
            }
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { value in
                        guard let point = guestPoint(value.location, in: rect) else { return }
                        onPoint?(point)
                    }
                    .onEnded { value in
                        guard let point = guestPoint(value.location, in: rect) else { return }
                        onClick?(point, true)
                        onClick?(point, false)
                    }
            )
        }
        .background(Color.black)
    }

    private var waiting: some View {
        VStack(spacing: 10) {
            ProgressView()
            Text(display.isAttached ? "Waiting for the first frame" : "Waiting for the display")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    /// The largest rectangle with the guest's aspect ratio that fits in `available`.
    private func fittedRect(in available: CGSize) -> CGRect {
        guard display.size.width > 0, display.size.height > 0 else {
            return CGRect(origin: .zero, size: available)
        }
        let scale = min(available.width / display.size.width, available.height / display.size.height)
        let size = CGSize(width: display.size.width * scale, height: display.size.height * scale)
        return CGRect(x: (available.width - size.width) / 2,
                      y: (available.height - size.height) / 2,
                      width: size.width,
                      height: size.height)
    }

    /// View coordinates to guest pixels, or nil for a point outside the screen.
    private func guestPoint(_ location: CGPoint, in rect: CGRect) -> CGPoint? {
        guard rect.width > 0, rect.height > 0, rect.contains(location) else { return nil }
        let x = (location.x - rect.minX) / rect.width * display.size.width
        let y = (location.y - rect.minY) / rect.height * display.size.height
        return CGPoint(x: x.rounded(), y: y.rounded())
    }
}
