// Renders the app icons. From the project folder:
//     swift Tools/icon/make_icon.swift Tools/icon/out
import AppKit
import CoreGraphics

let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func color(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat(hex >> 16 & 0xff) / 255, green: CGFloat(hex >> 8 & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

/// Shield centred at (cx, cy), `w` wide. Flat top with rounded shoulders,
/// sides curving to a point.
func shieldPath(cx: CGFloat, cy: CGFloat, w: CGFloat) -> CGPath {
    let h = w * 1.16
    let top = cy + h / 2, bottom = cy - h / 2
    let l = cx - w / 2, r = cx + w / 2
    let p = CGMutablePath()
    p.move(to: CGPoint(x: cx, y: top))
    p.addCurve(to: CGPoint(x: r, y: top - h * 0.12),
               control1: CGPoint(x: cx + w * 0.22, y: top - h * 0.05),
               control2: CGPoint(x: r - w * 0.12, y: top - h * 0.03))
    p.addCurve(to: CGPoint(x: cx, y: bottom),
               control1: CGPoint(x: r + w * 0.02, y: cy - h * 0.12),
               control2: CGPoint(x: cx + w * 0.30, y: bottom + h * 0.12))
    p.addCurve(to: CGPoint(x: l, y: top - h * 0.12),
               control1: CGPoint(x: cx - w * 0.30, y: bottom + h * 0.12),
               control2: CGPoint(x: l - w * 0.02, y: cy - h * 0.12))
    p.addCurve(to: CGPoint(x: cx, y: top),
               control1: CGPoint(x: l + w * 0.12, y: top - h * 0.03),
               control2: CGPoint(x: cx - w * 0.22, y: top - h * 0.05))
    p.closeSubpath()
    return p
}

/// A question mark built from a stroked hook and a dot, `s` tall.
func drawQuestion(_ ctx: CGContext, cx: CGFloat, cy: CGFloat, s: CGFloat, fill: CGColor, dotFill: CGColor? = nil) {
    let stroke = s * 0.17
    let r = s * 0.24
    let hookCenter = CGPoint(x: cx, y: cy + s * 0.20)
    let hook = CGMutablePath()
    hook.addArc(center: hookCenter, radius: r, startAngle: .pi * 0.95, endAngle: -.pi * 0.30, clockwise: true)
    // Down into the stem.
    let end = hook.currentPoint
    hook.addQuadCurve(to: CGPoint(x: cx, y: cy - s * 0.12),
                      control: CGPoint(x: cx + r * 0.05, y: end.y - r * 0.35))
    hook.addLine(to: CGPoint(x: cx, y: cy - s * 0.17))
    ctx.saveGState()
    ctx.setStrokeColor(fill)
    ctx.setLineWidth(stroke)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.addPath(hook)
    ctx.strokePath()
    ctx.setFillColor(dotFill ?? fill)
    let dot = stroke * 0.62
    ctx.fillEllipse(in: CGRect(x: cx - dot, y: cy - s * 0.40 - dot, width: dot * 2, height: dot * 2))
    ctx.restoreGState()
}

func render(size: Int, _ draw: (CGContext, CGFloat) -> Void) -> CGImage {
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    draw(ctx, CGFloat(size))
    return ctx.makeImage()!
}

func save(_ image: CGImage, _ name: String) {
    let rep = NSBitmapImageRep(cgImage: image)
    try! rep.representation(using: .png, properties: [:])!.write(to: out.appendingPathComponent(name))
}

/// The artwork inside a square of side `s` at origin `o`.
func artwork(_ ctx: CGContext, o: CGPoint, s: CGFloat) {
    let bg = CGGradient(colorsSpace: nil, colors: [color(0x0B1B3F), color(0x2A2F8F)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: o.x, y: o.y + s), end: CGPoint(x: o.x + s, y: o.y), options: [])
    // Teal glow behind the shield.
    let glow = CGGradient(colorsSpace: nil, colors: [color(0x2FD4C4, 0.55), color(0x2FD4C4, 0)] as CFArray, locations: [0, 1])!
    let c = CGPoint(x: o.x + s / 2, y: o.y + s * 0.49)
    ctx.drawRadialGradient(glow, startCenter: c, startRadius: 0, endCenter: c, endRadius: s * 0.48, options: [])

    let shield = shieldPath(cx: c.x, cy: c.y, w: s * 0.56)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.015), blur: s * 0.04, color: color(0x000000, 0.45))
    ctx.addPath(shield)
    ctx.setFillColor(color(0xFFFFFF))
    ctx.fillPath()
    ctx.restoreGState()
    // Faint inner edge so the shield reads as an object, not a cut-out.
    ctx.saveGState()
    ctx.addPath(shieldPath(cx: c.x, cy: c.y, w: s * 0.50))
    ctx.setStrokeColor(color(0x2A2F8F, 0.12))
    ctx.setLineWidth(s * 0.008)
    ctx.strokePath()
    ctx.restoreGState()

    drawQuestion(ctx, cx: c.x, cy: c.y + s * 0.01, s: s * 0.40, fill: color(0x1A2366), dotFill: color(0x14B8A6))
}

// iPhone / iPad: full bleed, the system masks the corners.
save(render(size: 1024) { ctx, s in artwork(ctx, o: .zero, s: s) }, "ios-1024.png")

// Mac: Apple's grid puts an 824-pt rounded square inside 1024 with a shadow.
for px in [16, 32, 64, 128, 256, 512, 1024] {
    save(render(size: px) { ctx, s in
        let inset = s * 100 / 1024, side = s - inset * 2
        let rect = CGRect(x: inset, y: inset + s * 0.01, width: side, height: side)
        let shape = CGPath(roundedRect: rect, cornerWidth: side * 0.225, cornerHeight: side * 0.225, transform: nil)
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.01), blur: s * 0.03, color: color(0x000000, 0.35))
        ctx.addPath(shape); ctx.setFillColor(color(0x0B1B3F)); ctx.fillPath()
        ctx.restoreGState()
        ctx.saveGState()
        ctx.addPath(shape); ctx.clip()
        artwork(ctx, o: rect.origin, s: side)
        ctx.restoreGState()
    }, "mac-\(px).png")
}

// Share-sheet action: a template, so only the alpha matters.
save(render(size: 1024) { ctx, s in
    let c = CGPoint(x: s / 2, y: s / 2)
    ctx.addPath(shieldPath(cx: c.x, cy: c.y, w: s * 0.80))
    ctx.setFillColor(color(0x000000))
    ctx.fillPath()
    ctx.setBlendMode(.clear)
    drawQuestion(ctx, cx: c.x, cy: c.y + s * 0.02, s: s * 0.56, fill: color(0x000000))
}, "action-1024.png")
print("ok")
