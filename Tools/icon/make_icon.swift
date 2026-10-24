// Renders the app icons. From the project folder:
//     swift Tools/icon/make_icon.swift Tools/icon/out
//
// Shapes and gradients only, no fonts or bitmaps, so everything stays sharp
// at any size. iPhone icons are written without an alpha channel
// (ITMS-90717); the Mac icon and the Share-action glyph need transparency.
import AppKit
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func color(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat(hex >> 16 & 0xff) / 255, green: CGFloat(hex >> 8 & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

func gradient(_ stops: [(UInt32, CGFloat)], alpha: CGFloat = 1) -> CGGradient {
    CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
               colors: stops.map { color($0.0, alpha) } as CFArray,
               locations: stops.map(\.1))!
}

/// One colour scheme: background, metal rim and shield face.
struct Palette {
    var name: String
    var bgCenter: UInt32, bgEdge: UInt32
    var rim: [UInt32]          // light → dark → light, for the bevel
    var faceTop: UInt32, faceBottom: UInt32
    var glow: UInt32
    var dot: UInt32
}

let palettes = [
    Palette(name: "", bgCenter: 0x1E3A8A, bgEdge: 0x050B24,
            rim: [0xF8FAFC, 0x94A3B8, 0x475569, 0xCBD5E1, 0xF1F5F9],
            faceTop: 0x2563EB, faceBottom: 0x0B1B4F, glow: 0x38BDF8, dot: 0x2DD4BF),
    Palette(name: "-orange", bgCenter: 0xEA580C, bgEdge: 0x3B0F04,
            rim: [0xFFF1E0, 0xFDBA74, 0xB45309, 0xFED7AA, 0xFFF7ED],
            faceTop: 0xFF8A1F, faceBottom: 0xC2410C, glow: 0xFFC078, dot: 0xFFF3C4),
    Palette(name: "-gold", bgCenter: 0xB7791F, bgEdge: 0x1F1404,
            rim: [0xFFFBEB, 0xFCD34D, 0xA16207, 0xFDE68A, 0xFFFDF2],
            faceTop: 0xFFC61A, faceBottom: 0xA16207, glow: 0xFFE08A, dot: 0xFFFFFF),
]

/// Heater shield: broad top with a slight peak, curving to a point.
func shieldPath(cx: CGFloat, cy: CGFloat, w: CGFloat) -> CGPath {
    let h = w * 1.18
    let top = cy + h / 2, bottom = cy - h / 2
    let l = cx - w / 2, r = cx + w / 2
    let p = CGMutablePath()
    p.move(to: CGPoint(x: cx, y: top))
    p.addCurve(to: CGPoint(x: r, y: top - h * 0.10),
               control1: CGPoint(x: cx + w * 0.20, y: top - h * 0.06),
               control2: CGPoint(x: r - w * 0.10, y: top - h * 0.02))
    p.addCurve(to: CGPoint(x: cx, y: bottom),
               control1: CGPoint(x: r + w * 0.02, y: cy - h * 0.14),
               control2: CGPoint(x: cx + w * 0.28, y: bottom + h * 0.10))
    p.addCurve(to: CGPoint(x: l, y: top - h * 0.10),
               control1: CGPoint(x: cx - w * 0.28, y: bottom + h * 0.10),
               control2: CGPoint(x: l - w * 0.02, y: cy - h * 0.14))
    p.addCurve(to: CGPoint(x: cx, y: top),
               control1: CGPoint(x: l + w * 0.10, y: top - h * 0.02),
               control2: CGPoint(x: cx - w * 0.20, y: top - h * 0.06))
    p.closeSubpath()
    return p
}

/// The question mark as a stroked hook plus a dot, `s` tall.
func questionPath(cx: CGFloat, cy: CGFloat, s: CGFloat) -> (hook: CGPath, dot: CGRect, width: CGFloat) {
    let stroke = s * 0.17
    let r = s * 0.24
    let hook = CGMutablePath()
    hook.addArc(center: CGPoint(x: cx, y: cy + s * 0.20), radius: r,
                startAngle: .pi * 0.95, endAngle: -.pi * 0.30, clockwise: true)
    let end = hook.currentPoint
    hook.addQuadCurve(to: CGPoint(x: cx, y: cy - s * 0.12),
                      control: CGPoint(x: cx + r * 0.05, y: end.y - r * 0.35))
    hook.addLine(to: CGPoint(x: cx, y: cy - s * 0.17))
    let d = stroke * 0.64
    return (hook, CGRect(x: cx - d, y: cy - s * 0.40 - d, width: d * 2, height: d * 2), stroke)
}

func render(size: Int, opaque: Bool, _ draw: (CGContext, CGFloat) -> Void) -> CGImage {
    let info = opaque ? CGImageAlphaInfo.noneSkipLast.rawValue : CGImageAlphaInfo.premultipliedLast.rawValue
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: info)!
    ctx.interpolationQuality = .high
    ctx.setShouldAntialias(true)
    draw(ctx, CGFloat(size))
    return ctx.makeImage()!
}

/// PNG via ImageIO so an opaque image is written as RGB, with no alpha channel.
func save(_ image: CGImage, _ name: String) {
    let url = out.appendingPathComponent(name) as CFURL
    let dest = CGImageDestinationCreateWithURL(url, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, image, nil)
    CGImageDestinationFinalize(dest)
}

/// The full artwork inside a square of side `s` at origin `o`.
func artwork(_ ctx: CGContext, o: CGPoint, s: CGFloat, p: Palette) {
    let c = CGPoint(x: o.x + s / 2, y: o.y + s * 0.49)

    // Background: radial light from behind the shield, fading to the edges.
    ctx.saveGState()
    ctx.addRect(CGRect(origin: o, size: CGSize(width: s, height: s)))
    ctx.clip()
    ctx.setFillColor(color(p.bgEdge))
    ctx.fill(CGRect(origin: o, size: CGSize(width: s, height: s)))
    ctx.drawRadialGradient(gradient([(p.bgCenter, 0), (p.bgEdge, 1)]),
                           startCenter: CGPoint(x: c.x, y: c.y + s * 0.08), startRadius: 0,
                           endCenter: c, endRadius: s * 0.78, options: [.drawsAfterEndLocation])

    // Light rays fanning out from behind the shield.
    let rays = 18
    for i in 0..<rays {
        let a0 = CGFloat(i) / CGFloat(rays) * .pi * 2
        let a1 = a0 + .pi / CGFloat(rays) * 0.55
        let ray = CGMutablePath()
        ray.move(to: c)
        ray.addLine(to: CGPoint(x: c.x + cos(a0) * s, y: c.y + sin(a0) * s))
        ray.addLine(to: CGPoint(x: c.x + cos(a1) * s, y: c.y + sin(a1) * s))
        ray.closeSubpath()
        ctx.saveGState()
        ctx.addPath(ray)
        ctx.clip()
        ctx.drawRadialGradient(gradient([(p.glow, 0), (p.glow, 1)], alpha: 1),
                               startCenter: c, startRadius: 0, endCenter: c, endRadius: s * 0.7, options: [])
        ctx.restoreGState()
    }
    // Fade the rays so they read as light, not stripes.
    ctx.drawRadialGradient(
        CGGradient(colorsSpace: nil, colors: [color(p.bgEdge, 0.70), color(p.bgEdge, 0.90), color(p.bgEdge, 1)] as CFArray,
                   locations: [0, 0.55, 1])!,
        startCenter: c, startRadius: 0, endCenter: c, endRadius: s * 0.75, options: [.drawsAfterEndLocation])

    // Soft halo behind the shield.
    ctx.drawRadialGradient(
        CGGradient(colorsSpace: nil, colors: [color(p.glow, 0.55), color(p.glow, 0)] as CFArray, locations: [0, 1])!,
        startCenter: c, startRadius: s * 0.05, endCenter: c, endRadius: s * 0.46, options: [])
    ctx.restoreGState()

    let w = s * 0.60
    let outer = shieldPath(cx: c.x, cy: c.y, w: w)
    let inner = shieldPath(cx: c.x, cy: c.y - s * 0.004, w: w * 0.84)

    // Drop shadow.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.025), blur: s * 0.06, color: color(0x000000, 0.65))
    ctx.addPath(outer)
    ctx.setFillColor(color(p.rim[2]))
    ctx.fillPath()
    ctx.restoreGState()

    // Metal rim: a diagonal multi-stop gradient reads as polished metal.
    ctx.saveGState()
    ctx.addPath(outer)
    ctx.clip()
    let rimStops = p.rim.enumerated().map { ($0.element, CGFloat($0.offset) / CGFloat(p.rim.count - 1)) }
    let box = outer.boundingBox
    ctx.drawLinearGradient(gradient(rimStops), start: CGPoint(x: box.minX, y: box.maxY),
                           end: CGPoint(x: box.maxX, y: box.minY), options: [])
    // Bevel: a thin bright edge along the top-left.
    ctx.addPath(outer)
    ctx.setStrokeColor(color(0xFFFFFF, 0.55))
    ctx.setLineWidth(s * 0.008)
    ctx.strokePath()
    ctx.restoreGState()

    // Inner groove between rim and face.
    ctx.saveGState()
    ctx.addPath(shieldPath(cx: c.x, cy: c.y - s * 0.004, w: w * 0.865))
    ctx.setFillColor(color(0x000000, 0.45))
    ctx.fillPath()
    ctx.restoreGState()

    // Face: deep enamel gradient.
    ctx.saveGState()
    ctx.addPath(inner)
    ctx.clip()
    let ib = inner.boundingBox
    ctx.drawLinearGradient(gradient([(p.faceTop, 0), (p.faceBottom, 1)]),
                           start: CGPoint(x: ib.midX, y: ib.maxY), end: CGPoint(x: ib.midX, y: ib.minY), options: [])
    // Inner glow at the centre of the face.
    ctx.drawRadialGradient(
        CGGradient(colorsSpace: nil, colors: [color(p.glow, 0.45), color(p.glow, 0)] as CFArray, locations: [0, 1])!,
        startCenter: CGPoint(x: c.x, y: c.y + s * 0.02), startRadius: 0,
        endCenter: CGPoint(x: c.x, y: c.y + s * 0.02), endRadius: s * 0.26, options: [])

    // The question mark, with a glow.
    let q = questionPath(cx: c.x, cy: c.y + s * 0.005, s: s * 0.36)
    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: s * 0.035, color: color(p.glow, 0.95))
    ctx.addPath(q.hook)
    ctx.setStrokeColor(color(0xFFFFFF))
    ctx.setLineWidth(q.width)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.strokePath()
    ctx.setFillColor(color(p.dot))
    ctx.fillEllipse(in: q.dot)
    ctx.restoreGState()

    // Glass highlight: a bright sweep across the top of the face.
    let gloss = CGMutablePath()
    gloss.addEllipse(in: CGRect(x: ib.minX - ib.width * 0.35, y: ib.midY + ib.height * 0.02,
                                width: ib.width * 1.7, height: ib.height * 0.95))
    ctx.addPath(gloss)
    ctx.clip()
    ctx.drawLinearGradient(
        CGGradient(colorsSpace: nil, colors: [color(0xFFFFFF, 0.34), color(0xFFFFFF, 0.03)] as CFArray, locations: [0, 1])!,
        start: CGPoint(x: ib.midX, y: ib.maxY), end: CGPoint(x: ib.midX, y: ib.midY), options: [])
    ctx.restoreGState()

    // Specular glint on the rim, top left.
    ctx.saveGState()
    let glint = CGPoint(x: box.minX + box.width * 0.22, y: box.maxY - box.height * 0.10)
    ctx.drawRadialGradient(
        CGGradient(colorsSpace: nil, colors: [color(0xFFFFFF, 0.9), color(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!,
        startCenter: glint, startRadius: 0, endCenter: glint, endRadius: s * 0.05, options: [])
    ctx.restoreGState()
}

for p in palettes {
    // iPhone / iPad: full bleed and opaque; the system masks the corners.
    save(render(size: 1024, opaque: true) { ctx, s in artwork(ctx, o: .zero, s: s, p: p) }, "ios\(p.name)-1024.png")

    // Mac: Apple's grid puts an 824-pt rounded square inside 1024 with a shadow.
    for px in [16, 32, 64, 128, 256, 512, 1024] {
        save(render(size: px, opaque: false) { ctx, s in
            let inset = s * 100 / 1024, side = s - inset * 2
            let rect = CGRect(x: inset, y: inset + s * 0.01, width: side, height: side)
            let shape = CGPath(roundedRect: rect, cornerWidth: side * 0.225, cornerHeight: side * 0.225, transform: nil)
            ctx.saveGState()
            ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.01), blur: s * 0.03, color: color(0x000000, 0.35))
            ctx.addPath(shape); ctx.setFillColor(color(p.bgEdge)); ctx.fillPath()
            ctx.restoreGState()
            ctx.saveGState()
            ctx.addPath(shape); ctx.clip()
            artwork(ctx, o: rect.origin, s: side, p: p)
            ctx.restoreGState()
        }, "mac\(p.name)-\(px).png")
    }
}

// Share-sheet action: a template, so only the alpha matters.
save(render(size: 1024, opaque: false) { ctx, s in
    let c = CGPoint(x: s / 2, y: s / 2)
    ctx.addPath(shieldPath(cx: c.x, cy: c.y, w: s * 0.78))
    ctx.setFillColor(color(0x000000))
    ctx.fillPath()
    ctx.setBlendMode(.clear)
    let q = questionPath(cx: c.x, cy: c.y + s * 0.02, s: s * 0.56)
    ctx.addPath(q.hook)
    ctx.setLineWidth(q.width)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.strokePath()
    ctx.fillEllipse(in: q.dot)
}, "action-1024.png")
print("ok")
