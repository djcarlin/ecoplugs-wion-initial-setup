import AppKit
import Darwin

struct SetupError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct TimerConnection {
    let host: String
    let interfaceIndex: UInt32
    let address: String
    let port: UInt16
    let identity: Data
    let isSetup: Bool

    var name: String { String(decoding: identity[6..<38].prefix { $0 != 0 }, as: UTF8.self) }

    static func discover(setupOnly: Bool = false, lanOnly: Bool = false, matching name: String? = nil) throws -> Self {
        let timers = try discoverAll(setupOnly: setupOnly, lanOnly: lanOnly, matching: name)
        guard timers.count == 1, let timer = timers.first else {
            throw SetupError("Choose one ECO timer.")
        }
        return timer
    }

    static func discoverAll(setupOnly: Bool = false, lanOnly: Bool = false, matching name: String? = nil) throws -> [Self] {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let first = interfaces else {
            throw SetupError("Could not read the Mac’s network interfaces.")
        }
        defer { freeifaddrs(first) }
        var candidates: [(host: String, address: String, index: UInt32, setup: Bool)] = []
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = current {
            let interface = entry.pointee
            current = interface.ifa_next
            guard let address = interface.ifa_addr, address.pointee.sa_family == AF_INET,
                  interface.ifa_flags & UInt32(IFF_UP) != 0 else { continue }
            let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                String(cString: inet_ntoa($0.pointee.sin_addr))
            }
            let index = if_nametoindex(interface.ifa_name)
            guard interface.ifa_flags & UInt32(IFF_BROADCAST) != 0, index != 0 else { continue }
            let parts = ip.split(separator: ".")
            if !lanOnly, parts.count == 4, parts[0] == "192", parts[1] == "168",
               ["4", "5"].contains(parts[2]), parts[3] != "1" {
                candidates.append((parts.prefix(3).joined(separator: ".") + ".1", ip, index, true))
            }
            if !setupOnly, let broadcast = interface.ifa_dstaddr, broadcast.pointee.sa_family == AF_INET {
                let target = broadcast.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    String(cString: inet_ntoa($0.pointee.sin_addr))
                }
                if target != "0.0.0.0", target != ip {
                    candidates.append((target, ip, index, false))
                }
            }
        }
        var found: [String: Self] = [:]
        for candidate in candidates.sorted(by: { $0.setup && !$1.setup }) {
            if !candidate.setup && found.values.contains(where: { $0.isSetup }) { break }
            _ = try exchange(host: candidate.host, interfaceIndex: candidate.index, address: candidate.address,
                             sourcePort: 8900, ports: [25, 5888], message: discoveryMessage(),
                             timeout: 1.2, broadcast: !candidate.setup) { data, _, sender in
                guard data.count == 408, !lanOnly || !["192.168.4.1", "192.168.5.1"].contains(sender) else { return false }
                let id = String(decoding: data[10..<42].prefix { $0 != 0 }, as: UTF8.self)
                let port = number(data, 404, 4)
                guard id.hasPrefix("ECO-"), id.count > 4,
                      id.utf8.allSatisfy({
                          (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
                      }), (1...65535).contains(port), name == nil || name == id else { return false }
                found[id] = Self(host: sender, interfaceIndex: candidate.index, address: candidate.address,
                                 port: UInt16(port), identity: Data(data[4..<106]), isSetup: candidate.setup)
                return candidate.setup || name != nil
            }
        }
        guard !found.isEmpty else {
            throw SetupError("No ECO timer replied. Connect to its home or setup Wi-Fi and try again.")
        }
        return found.values.sorted { $0.name < $1.name }
    }

    fileprivate func settings(session: CommandSession? = nil) throws -> Data {
        guard let response = try command(0x50005, payload: Data(), session: session),
              response.count == 492, number(response, 8, 2) == 364,
              response[134..<166] == identity[6..<38] else {
            throw SetupError("The timer did not return a matching settings record.")
        }
        return Data(response[128..<492])
    }

    func scan() throws {
        let session = try CommandSession(address: address, interfaceIndex: interfaceIndex)
        _ = try settings(session: session)
        try scan(session: session)
    }

    private func scan(session: CommandSession) throws {
        guard let response = try command(0x50012, payload: Data(), session: session, timeout: 6),
              response.count == 1104, number(response, 8, 2) == 976 else {
            throw SetupError("The timer did not finish its Wi-Fi scan. Click Find Timer and try again.")
        }
    }

    func update(_ setup: SetupValues) throws -> (acknowledged: Bool, notices: [String]) {
        let solarTable = try setup.solarTable()
        let timer = try Self.discover(setupOnly: true, matching: name)
        guard timer.host == host, timer.interfaceIndex == interfaceIndex,
              timer.identity[6..<38] == identity[6..<38] else {
            throw SetupError("The connected timer changed. Click Find Timer and try again.")
        }
        let session = try CommandSession(address: timer.address, interfaceIndex: timer.interfaceIndex)
        let record = try timer.settings(session: session)
        try timer.scan(session: session)
        var notices: [String] = []
        // The original app initializes night-light channel 1 to off.
        let setupSteps: [(UInt32, Data, String)] = [
            (0x5001B, Data([1, 0]), "night-light setting"),
            (0x50018, solarTable, "sunrise/sunset table"),
        ]
        let updated = setup.record(from: record)
        let updatedIdentity = Data(updated.prefix(102))

        func sendSetup(attempts: Int = 1) throws -> Data? {
            for (code, payload, label) in setupSteps {
                if let reply = try timer.command(code, payload: payload, session: session, timeout: 0.15,
                                                 checkResult: false, copies: 2) {
                    let status = number(reply, 4, 2)
                    if status != 0 {
                        let notice = "The timer refused the \(label) (code \(status))."
                        if !notices.contains(notice) { notices.append(notice) }
                    }
                }
            }
            return try timer.command(0x50004, payload: updated, session: session, timeout: 2,
                                     checkResult: false, copies: 2, attempts: attempts, commandIdentity: updatedIdentity)
        }

        let response = try sendSetup(attempts: 2)
        let started = ProcessInfo.processInfo.systemUptime - 3
        for index in 1...4 {
            let delay = started + Double(index * 3) - ProcessInfo.processInfo.systemUptime
            if delay > 0 { Thread.sleep(forTimeInterval: delay) }
            guard let status = try? timer.command(0x50105, payload: Data(), session: session, timeout: 1,
                                                  checkResult: false, copies: 2, commandIdentity: updatedIdentity)
            else { continue }
            guard number(status, 4, 2) == 0 else { continue }
            // Android sends the complete settings sequence again when setup status succeeds.
            do {
                _ = try sendSetup()
            } catch {
                notices.append("The timer disconnected during the second setup write.")
            }
            return (true, notices)
        }
        if let response, number(response, 4, 2) == 3 {
            notices.append("The timer refused the first Wi-Fi settings write (code 3).")
        }
        notices.append("The timer did not report setup complete on its ECO network.")
        return (false, notices)
    }

    func displayName() throws -> String {
        let record = try settings()
        return String(decoding: record[38..<70].prefix { $0 != 0 }, as: UTF8.self)
    }

    func rename(to newName: String) throws {
        let timer = try Self.discover(matching: name)
        let session = try CommandSession(address: timer.address, interfaceIndex: timer.interfaceIndex)
        let record = try timer.settings(session: session)
        var payload = Data(repeating: 0, count: 102)
        payload.replaceSubrange(38..<70, with: padded(newName, length: 32))
        payload.replaceSubrange(70..<102, with: record[70..<102])
        _ = try timer.command(0x50013, payload: payload, session: session)
        let updated = try timer.settings(session: session)
        guard updated[38..<70].prefix(while: { $0 != 0 }).elementsEqual(newName.utf8) else {
            throw SetupError("The timer still reports its previous name. Click Find Timer to refresh it.")
        }
    }

    func timeZone() throws -> (offset: Int, dst: Bool) {
        let record = try settings()
        return (Int(Int32(bitPattern: number(record, 112, 4))) + 28_800,
                number(record, 104, 2) & 0x1000 != 0)
    }

    func setTimeZone(offset: Int, dst: Bool) throws {
        let timer = try Self.discover(matching: name)
        let session = try CommandSession(address: timer.address, interfaceIndex: timer.interfaceIndex)
        let payload = timeZonePayload(offset: offset, dst: dst)
        guard try timer.command(0x50015, payload: payload, session: session) != nil else {
            throw SetupError("The timer did not acknowledge the time-zone update.")
        }
        let saved = try timer.timeZone()
        guard saved.offset == offset && saved.dst == dst else {
            throw SetupError("The timer reports UTC\(offsetText(saved.offset)) after the update.")
        }
    }

    private func command(_ code: UInt32, payload: Data, session: CommandSession? = nil,
                         timeout: Double = 3, checkResult: Bool = true, copies: Int = 1,
                         attempts: Int = 1, commandIdentity: Data? = nil) throws -> Data? {
        let connection = try session ?? CommandSession(address: address, interfaceIndex: interfaceIndex)
        let sequence = UInt32.random(in: 1..<32728)
        var message = Data(repeating: 0, count: 128)
        write(code, to: &message, at: 0, count: 4)
        write(sequence, to: &message, at: 6, count: 2)
        write(UInt32(payload.count), to: &message, at: 8, count: 2)
        message.replaceSubrange(10..<112, with: commandIdentity ?? identity)
        write(UInt32(truncatingIfNeeded: Int64(Date().timeIntervalSince1970 * 1000)),
              to: &message, at: 116, count: 4)
        write(connection.clientID, to: &message, at: 124, count: 4)
        message.append(payload)
        var response: Data?
        for _ in 0..<attempts {
            response = try Self.exchange(host: host, interfaceIndex: interfaceIndex, address: address,
                                         sourcePort: 0, ports: [port], message: message, timeout: timeout,
                                         session: connection, copies: copies) { data, sender, _ in
                sender == port && data.count >= 128 && number(data, 0, 4) == code
                    && number(data, 6, 2) == sequence
            }
            if response != nil { break }
        }
        if checkResult, let response {
            let result = number(response, 4, 2)
            if result == 3 && code == 0x50004 {
                throw SetupError("The timer refused the Wi-Fi change (code 3). Its firmware did not say why.")
            }
            if result != 0 && !(code == 0x50004 && result == 6) {
                throw SetupError("The timer rejected the request (code \(result)).")
            }
        }
        return response
    }

    private static func discoveryMessage() -> Data {
        let date = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute, .second], from: Date())
        var request = Data(repeating: 0, count: 128)
        write(UInt32(date.year ?? 2026), to: &request, at: 24, count: 2)
        request[26] = UInt8(date.month ?? 1)
        request[27] = UInt8(date.day ?? 1)
        let seconds = (date.hour ?? 0) * 3600 + (date.minute ?? 0) * 60 + (date.second ?? 0)
        write(UInt32(seconds), to: &request, at: 28, count: 4)
        return request
    }

    private static func exchange(host: String, interfaceIndex: UInt32, address: String,
                                 sourcePort: UInt16, ports: [UInt16], message: Data, timeout: Double,
                                 session: CommandSession? = nil, broadcast: Bool = false, copies: Int = 1,
                                 accept: (Data, UInt16, String) -> Bool) throws -> Data? {
        let connection = try session ?? CommandSession(address: address, interfaceIndex: interfaceIndex, sourcePort: sourcePort)
        let descriptor = connection.descriptor
        if broadcast {
            var enabled: Int32 = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_BROADCAST, &enabled, 4) == 0 else {
                throw SetupError("Could not enable local discovery.")
            }
        }
        var didSend = false
        for port in ports {
            var remote = endpoint(host, port)
            for _ in 0..<copies {
                let sent = withUnsafePointer(to: &remote) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { target in
                        message.withUnsafeBytes {
                            sendto(descriptor, $0.baseAddress, $0.count, 0, target,
                                   socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }
                didSend = didSend || sent == message.count
            }
        }
        guard didSend else { throw SetupError("Could not send to the timer over local Wi-Fi.") }

        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var buffer = [UInt8](repeating: 0, count: 2048)
        while ProcessInfo.processInfo.systemUptime < deadline {
            let remaining = max(1, Int32((deadline - ProcessInfo.processInfo.systemUptime) * 1000))
            var event = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            guard poll(&event, 1, remaining) > 0 else { return nil }
            var sender = sockaddr_in()
            var size = socklen_t(MemoryLayout<sockaddr_in>.size)
            let received = withUnsafeMutablePointer(to: &sender) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(descriptor, &buffer, buffer.count, MSG_DONTWAIT, $0, &size)
                }
            }
            guard received > 0, (broadcast || sender.sin_addr.s_addr == inet_addr(host)) else { continue }
            let data = Data(buffer.prefix(received))
            if accept(data, UInt16(bigEndian: sender.sin_port), String(cString: inet_ntoa(sender.sin_addr))) { return data }
        }
        return nil
    }
}

private final class CommandSession {
    let descriptor: Int32
    let clientID = UInt32.random(in: 1...UInt32(Int32.max))

    init(address: String, interfaceIndex: UInt32, sourcePort: UInt16 = 0) throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard descriptor >= 0 else { throw SetupError("Could not open a UDP socket.") }
        var ready = false
        defer { if !ready { close(descriptor) } }
        var index = interfaceIndex
        guard setsockopt(descriptor, IPPROTO_IP, IP_BOUND_IF, &index, 4) == 0 else {
            throw SetupError("Could not select the timer’s network interface.")
        }
        var local = endpoint(address, sourcePort)
        let bound = withUnsafePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            throw SetupError("Could not open the timer’s local connection (\(String(cString: strerror(errno)))).")
        }
        self.descriptor = descriptor
        ready = true
    }

    deinit { close(descriptor) }
}

private extension Data {
    var rebased: Data { Data(self) }
}

private func endpoint(_ ip: String, _ port: UInt16) -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr.s_addr = inet_addr(ip)
    return address
}

private func number(_ data: Data, _ offset: Int, _ count: Int) -> UInt32 {
    (0..<count).reduce(0) { $0 | (UInt32(data[offset + $1]) << ($1 * 8)) }
}

private func write(_ value: UInt32, to data: inout Data, at offset: Int, count: Int) {
    for byte in 0..<count {
        data[offset + byte] = UInt8(truncatingIfNeeded: value >> (byte * 8))
    }
}

private func padded(_ value: String, length: Int = 64) -> Data {
    Data(value.utf8) + Data(repeating: 0, count: length - value.utf8.count)
}

private func offsetText(_ seconds: Int) -> String {
    let minutes = abs(seconds) / 60
    return String(format: "%@%02d:%02d", seconds < 0 ? "-" : "+", minutes / 60, minutes % 60)
}

private func parseOffset(_ text: String) -> Int? {
    guard text.first == "+" || text.first == "-" else { return nil }
    let parts = text.dropFirst().split(separator: ":", omittingEmptySubsequences: false)
    guard parts.count == 2, parts.allSatisfy({ $0.count == 2 && $0.utf8.allSatisfy { (48...57).contains($0) } }),
          let hours = Int(parts[0]), let minutes = Int(parts[1]), minutes < 60 else { return nil }
    let offset = (hours * 3600 + minutes * 60) * (text.first == "-" ? -1 : 1)
    return (-43_200...50_400).contains(offset) ? offset : nil
}

private func timeZonePayload(offset: Int, dst: Bool) -> Data {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(secondsFromGMT: offset)!
    let components = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: Date())
    var payload = Data(repeating: 0, count: 12)
    write(UInt32(components.year!) | (dst ? 0x1000 : 0), to: &payload, at: 0, count: 2)
    payload[2] = UInt8(components.month!)
    payload[3] = UInt8(components.day!)
    let seconds = components.hour! * 3600 + components.minute! * 60 + components.second!
    write(UInt32(seconds), to: &payload, at: 4, count: 4)
    write(UInt32(bitPattern: Int32(offset - 28_800)), to: &payload, at: 8, count: 4)
    return payload
}

struct SetupValues {
    let ssid: String
    let password: String
    let name: String
    let offset: Int
    let daylightSaving: Bool
    let zip: String

    func solarTable() throws -> Data {
        var coordinates: (latitude: Double, longitude: Double)?
        if !zip.isEmpty {
            guard let url = Bundle.main.url(forResource: "zip-coordinates", withExtension: "csv") else {
                throw SetupError("The app’s ZIP coordinate file is missing.")
            }
            let lookup = try String(contentsOf: url, encoding: .utf8)
            let row = lookup.split(separator: "\n").first { $0.hasPrefix(zip + ",") }
            let fields = row?.split(separator: ",") ?? []
            guard fields.count == 3, let latitude = Double(fields[1]), let longitude = Double(fields[2]) else {
                throw SetupError("No coordinates were found for ZIP \(zip).")
            }
            coordinates = (latitude, longitude)
        }

        var table = Data()
        table.reserveCapacity(366 * 3)
        for day in 0..<366 {
            var sunrise = 360
            var sunset = 1080
            if let coordinates {
                // NOAA fractional-year approximation, in local standard time.
                let angle = 2 * Double.pi * Double(day) / 366
                let equationOfTime = 229.18 * (0.000075 + 0.001868 * cos(angle) - 0.032077 * sin(angle)
                    - 0.014615 * cos(2 * angle) - 0.040849 * sin(2 * angle))
                let declination = 0.006918 - 0.399912 * cos(angle) + 0.070257 * sin(angle)
                    - 0.006758 * cos(2 * angle) + 0.000907 * sin(2 * angle)
                    - 0.002697 * cos(3 * angle) + 0.00148 * sin(3 * angle)
                let latitude = coordinates.latitude * .pi / 180
                let cosine = (cos(90.833 * .pi / 180) - sin(latitude) * sin(declination))
                    / (cos(latitude) * cos(declination))
                guard (-1...1).contains(cosine) else {
                    throw SetupError("This ZIP has days without sunrise or sunset. The timer’s table needs both.")
                }
                let noon = 720 - 4 * coordinates.longitude - equationOfTime + Double(offset) / 60
                let minutesToHorizon = acos(cosine) * 720 / .pi
                sunrise = (Int(floor(noon - minutesToHorizon)) % 1440 + 1440) % 1440
                sunset = (Int(floor(noon + minutesToHorizon)) % 1440 + 1440) % 1440
            }
            let packed = (sunrise << 12) | sunset
            table.append(UInt8(truncatingIfNeeded: packed))
            table.append(UInt8(truncatingIfNeeded: packed >> 8))
            table.append(UInt8(truncatingIfNeeded: packed >> 16))
        }
        return table
    }

    func record(from existing: Data) -> Data {
        var updated = existing
        updated.replaceSubrange(38..<70, with: padded(name, length: 32))
        updated.replaceSubrange(104..<116, with: timeZonePayload(offset: offset, dst: daylightSaving))
        updated.replaceSubrange(116..<180, with: padded(ssid))
        updated.replaceSubrange(180..<244, with: padded(password))
        if let zipNumber = Int(zip) {
            updated.replaceSubrange(246..<256, with: padded("001", length: 10))
            updated.replaceSubrange(256..<266, with: padded(String(zipNumber), length: 10))
        }
        return updated
    }

    func unverifiedFields(in record: Data) -> [String] {
        var fields: [String] = []
        if !record[116..<180].prefix(while: { $0 != 0 }).elementsEqual(ssid.utf8) {
            fields.append("saved Wi-Fi name")
        }
        if !record[38..<70].prefix(while: { $0 != 0 }).elementsEqual(name.utf8) {
            fields.append("name")
        }
        if Int(Int32(bitPattern: number(record, 112, 4))) + 28_800 != offset
            || (number(record, 104, 2) & 0x1000 != 0) != daylightSaving {
            fields.append("time zone")
        }
        if let zipNumber = Int(zip),
           !record[246..<256].prefix(while: { $0 != 0 }).elementsEqual("001".utf8)
           || !record[256..<266].prefix(while: { $0 != 0 }).elementsEqual(String(zipNumber).utf8) {
            fields.append("ZIP code")
        }
        return fields
    }
}

final class SetupWindow: NSObject, NSApplicationDelegate {
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 535),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
    let status = NSTextField(wrappingLabelWithString: "")
    let alias = NSTextField()
    let devices = NSPopUpButton()
    var discovered: [TimerConnection] = []
    let ssid = NSTextField()
    let password = NSSecureTextField()
    let setupOffset = NSTextField()
    let setupDST = NSButton(checkboxWithTitle: "Daylight saving", target: nil, action: nil)
    let setupZIP = NSTextField()
    lazy var find = NSButton(title: "Find Timer", target: self, action: #selector(discover))
    lazy var apply = NSButton(title: "Apply Setup", target: self, action: #selector(save))
    lazy var renameButton = NSButton(title: "Save Name", target: self, action: #selector(rename))
    lazy var zoneButton = NSButton(title: "Time Zone…", target: self, action: #selector(editTimeZone))
    var timer: TimerConnection?

    func applicationDidFinishLaunching(_ notification: Notification) {
        window.title = "WiOn Setup"
        window.center()

        let content = NSView()
        window.contentView = content
        let title = NSTextField(labelWithString: "Manage your WiOn timer")
        title.font = .systemFont(ofSize: 24, weight: .semibold)
        let help = NSTextField(wrappingLabelWithString: "Initial setup requires the timer’s ECO Wi-Fi. Enter the 2.4 GHz network it should join.")
        help.textColor = .secondaryLabelColor
        devices.target = self
        devices.action = #selector(selectDevice)
        devices.setAccessibilityLabel("ECO timer")
        alias.placeholderString = "Timer name"
        alias.setAccessibilityLabel("Timer name")
        let nameRow = NSStackView(views: [alias, renameButton])
        nameRow.orientation = .horizontal
        nameRow.spacing = 10
        let separator = NSBox()
        separator.boxType = .separator
        ssid.placeholderString = "Network name (SSID)"
        ssid.setAccessibilityLabel("Network name (SSID)")
        password.placeholderString = "Password (leave blank for an open network)"
        password.setAccessibilityLabel("Wi-Fi password")
        let zone = TimeZone.current
        let now = Date()
        let standardOffset = zone.secondsFromGMT(for: now) - Int(zone.daylightSavingTimeOffset(for: now))
        setupOffset.stringValue = offsetText(standardOffset)
        setupOffset.setAccessibilityLabel("Standard UTC offset")
        setupDST.state = zone.isDaylightSavingTime(for: now) || zone.nextDaylightSavingTimeTransition(after: now) != nil ? .on : .off
        let zoneLabel = NSTextField(labelWithString: "Standard UTC offset")
        let clockRow = NSStackView(views: [zoneLabel, setupOffset, setupDST])
        clockRow.orientation = .horizontal
        clockRow.spacing = 10
        setupOffset.widthAnchor.constraint(equalToConstant: 78).isActive = true
        setupZIP.placeholderString = "US ZIP code (optional)"
        setupZIP.setAccessibilityLabel("US ZIP code")
        let locationHelp = NSTextField(wrappingLabelWithString: "ZIP supplies sunrise and sunset times. Leave it blank to use the original app’s 6 AM and 6 PM defaults.")
        locationHelp.textColor = .secondaryLabelColor
        status.textColor = .secondaryLabelColor
        let buttons = NSStackView(views: [find, apply, zoneButton])
        buttons.orientation = .horizontal
        buttons.spacing = 10


        let stack = NSStackView(views: [title, devices, nameRow, separator, help, ssid, password, clockRow, setupZIP, locationHelp, buttons, status])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 26),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -26),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 26),
            nameRow.widthAnchor.constraint(equalTo: stack.widthAnchor),
            separator.widthAnchor.constraint(equalTo: stack.widthAnchor),
            ssid.widthAnchor.constraint(equalTo: stack.widthAnchor),
            password.widthAnchor.constraint(equalTo: stack.widthAnchor),
            setupZIP.widthAnchor.constraint(equalTo: stack.widthAnchor),
            locationHelp.widthAnchor.constraint(equalTo: stack.widthAnchor),
            status.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        discover()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    @objc func discover() {
        let previous = timer?.name
        timer = nil
        devices.removeAllItems()
        busy(true, "Looking for timers on local Wi-Fi…")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try TimerConnection.discoverAll() }
            DispatchQueue.main.async {
                switch result {
                case .success(let timers):
                    self.discovered = timers
                    self.devices.addItems(withTitles: timers.map { "\($0.name)  ·  \($0.host)" })
                    self.devices.selectItem(at: timers.firstIndex { $0.name == previous } ?? 0)
                    self.selectDevice()
                case .failure(let error):
                    self.busy(false, error.localizedDescription)
                }
            }
        }
    }

    @objc func selectDevice() {
        let index = devices.indexOfSelectedItem
        guard discovered.indices.contains(index) else { return }
        let selected = discovered[index]
        timer = nil
        alias.stringValue = ""
        busy(true, "Reading the timer’s name…")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try selected.displayName() }
            DispatchQueue.main.async {
                switch result {
                case .success(let name):
                    self.timer = selected
                    self.alias.stringValue = name
                    let hint = selected.isSetup ? "" : " Join the timer’s ECO setup Wi-Fi to change its network."
                    self.busy(false, "Found \(selected.name)." + hint)
                case .failure(let error):
                    self.busy(false, error.localizedDescription)
                }
            }
        }
    }

    @objc func rename() {
        guard let timer else { return }
        let newName = alias.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...30).contains(newName.utf8.count), !newName.utf8.contains(0) else {
            status.stringValue = "Enter a timer name of 1 to 30 UTF-8 bytes."
            return
        }
        busy(true, "Saving the timer name…")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try timer.rename(to: newName) }
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self.alias.stringValue = newName
                    self.busy(false, "Saved and verified the timer name.")
                case .failure(let error):
                    self.busy(false, error.localizedDescription)
                }
            }
        }
    }

    @objc func editTimeZone() {
        guard let timer else { return }
        busy(true, "Reading the timer’s time zone…")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result { try timer.timeZone() }
            DispatchQueue.main.async {
                switch result {
                case .success(let zone):
                    self.busy(false, "Timer reports UTC\(offsetText(zone.offset)).")
                    self.showTimeZone(for: timer, offset: zone.offset, dst: zone.dst)
                case .failure(let error):
                    self.busy(false, error.localizedDescription)
                }
            }
        }
    }

    private func showTimeZone(for timer: TimerConnection, offset: Int, dst: Bool) {
        let alert = NSAlert()
        alert.messageText = "Set timer time zone"
        alert.informativeText = "Enter the standard UTC offset, such as -05:00 for US Eastern."
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        let field = NSTextField(string: offsetText(offset))
        field.setAccessibilityLabel("Standard UTC offset")
        let daylight = NSButton(checkboxWithTitle: "Enable daylight saving time", target: nil, action: nil)
        daylight.state = dst ? .on : .off
        let controls = NSStackView(views: [field, daylight])
        controls.orientation = .vertical
        controls.alignment = .leading
        controls.spacing = 8
        field.widthAnchor.constraint(equalToConstant: 130).isActive = true
        controls.frame = NSRect(origin: .zero, size: controls.fittingSize)
        alert.accessoryView = controls
        alert.beginSheetModal(for: window) { result in
            guard result == .alertFirstButtonReturn else { return }
            guard let selected = parseOffset(field.stringValue.trimmingCharacters(in: .whitespaces)) else {
                self.busy(false, "Enter a signed UTC offset from -12:00 through +14:00.")
                return
            }
            let dst = daylight.state == .on
            self.busy(true, "Saving the timer’s time zone…")
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { try timer.setTimeZone(offset: selected, dst: dst) }
                DispatchQueue.main.async {
                    switch result {
                    case .success:
                        self.busy(false, "Verified UTC\(offsetText(selected)) on the timer.")
                    case .failure(let error):
                        self.busy(false, error.localizedDescription)
                    }
                }
            }
        }
    }

    @objc func save() {
        guard let timer else { return }
        let network = ssid.stringValue
        let secret = password.stringValue
        let name = alias.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let zip = setupZIP.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...30).contains(name.utf8.count), !name.utf8.contains(0) else {
            status.stringValue = "Enter a timer name of 1 to 30 UTF-8 bytes."
            return
        }
        guard let offset = parseOffset(setupOffset.stringValue.trimmingCharacters(in: .whitespaces)) else {
            status.stringValue = "Enter a standard UTC offset from -12:00 through +14:00."
            return
        }
        guard zip.isEmpty || (zip.utf8.count == 5 && zip.utf8.allSatisfy { (48...57).contains($0) } && zip != "00000") else {
            status.stringValue = "Enter a five-digit US ZIP code or leave it blank."
            return
        }
        guard (1...32).contains(network.utf8.count), !network.utf8.contains(0) else {
            status.stringValue = "Enter a network name of 1 to 32 bytes."
            return
        }
        let isPassphrase = (8...63).contains(secret.utf8.count)
            && secret.utf8.allSatisfy { (32...126).contains($0) }
        let isHexKey = secret.utf8.count == 64 && secret.utf8.allSatisfy {
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }
        guard secret.isEmpty || isPassphrase || isHexKey else {
            status.stringValue = "Use 8 to 63 printable ASCII characters or a 64-digit hex key."
            return
        }
        let setup = SetupValues(ssid: network, password: secret, name: name, offset: offset,
                                daylightSaving: setupDST.state == .on, zip: zip)
        password.stringValue = ""
        busy(true, "Sending setup settings to \(timer.name)…")
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try timer.update(setup)
                let note = result.notices.isEmpty ? "" : " " + result.notices.joined(separator: " ")
                DispatchQueue.main.async {
                    self.timer = nil
                    self.busy(true, "Looking for \(timer.name) on your home Wi-Fi. Reconnect this Mac if needed.")
                }
                var found: TimerConnection?
                var unverified: [String] = ["name and time zone"]
                let deadline = Date().addingTimeInterval(28)
                repeat {
                    if let joined = try? TimerConnection.discover(lanOnly: true, matching: timer.name) {
                        found = joined
                        if let record = try? joined.settings() {
                            unverified = setup.unverifiedFields(in: record)
                            if unverified.isEmpty { break }
                        }
                    }
                    Thread.sleep(forTimeInterval: 2)
                } while Date() < deadline
                let joined = found
                let remaining = unverified
                DispatchQueue.main.async {
                    guard let joined else {
                        let summary = result.acknowledged ? "The timer acknowledged setup." : "The setup request was sent."
                        self.busy(false, summary + " Join your home Wi-Fi and click Find Timer to check." + note)
                        return
                    }
                    self.timer = joined
                    self.discovered = [joined]
                    self.devices.removeAllItems()
                    self.devices.addItem(withTitle: "\(joined.name)  ·  \(joined.host)")
                    let detail = remaining.isEmpty ? (setup.zip.isEmpty ? " Saved Wi-Fi name, timer name and time zone verified." : " Saved Wi-Fi name, timer name, time zone and ZIP verified.") :
                        " Could not verify \(remaining.joined(separator: ", "))."
                    self.busy(false, "Found \(joined.name) at \(joined.host)." + detail + note)
                }
            } catch {
                DispatchQueue.main.async {
                    self.busy(false, error.localizedDescription)
                }
            }
        }
    }

    private func busy(_ busy: Bool, _ message: String) {
        find.isEnabled = !busy
        devices.isEnabled = !busy && devices.numberOfItems > 1
        let canSetWiFi = !busy && timer?.isSetup == true
        apply.isEnabled = canSetWiFi
        ssid.isEnabled = canSetWiFi
        password.isEnabled = canSetWiFi
        setupOffset.isEnabled = canSetWiFi
        setupDST.isEnabled = canSetWiFi
        setupZIP.isEnabled = canSetWiFi
        zoneButton.isEnabled = !busy && timer?.isSetup == false
        renameButton.isEnabled = !busy && timer?.isSetup == false
        alias.isEnabled = !busy && timer != nil
        status.stringValue = message
    }
}

if CommandLine.arguments.contains("--check-name") {
    do {
        let timer = try TimerConnection.discover(matching: CommandLine.arguments.last)
        print("Read the display name for \(timer.name) at \(timer.host): \(try timer.displayName())")
    } catch {
        fputs("\(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else if CommandLine.arguments.contains("--check") {
    do {
        let timer = try TimerConnection.discover(setupOnly: true)
        try timer.scan()
        print("Completed setup scan and read settings from \(timer.name) at \(timer.host) via \(timer.address).")
    } catch {
        fputs("\(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else {
    let app = NSApplication.shared
    let delegate = SetupWindow()
    app.delegate = delegate
    app.setActivationPolicy(.regular)
    app.run()
}
