import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root

  moduleName: "ucmz851.omascan"
  ipcTarget: "ucmz851.omascan"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.45)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // Scan state
  property string inputUrl: ""
  property string target: ""
  property string targetType: ""
  property string targetTypeLabel: ""
  property string lastScannedDomain: ""
  property string verdict: "READY" // "READY" | "CLEAN" | "SUSPICIOUS" | "MALICIOUS"
  property string verdictColor: "normal"
  property string verdictText: "Enter a URL, IP, or file hash (MD5/SHA-256) to inspect."
  property var dnsIps: []
  property var ssl: ({})
  property var http: ({})
  property var vt: ({})
  property var urlscan: ({})
  property var history: []
  property bool isScanning: false
  property string activeTab: "scan" // "scan" | "history" | "keys"

  // API Keys
  property string vtKeyInput: ""
  property string urlscanKeyInput: ""
  property bool hasVtKey: false
  property bool hasUrlscanKey: false
  property string keySavedNotice: ""

  function getVerdictColor(col) {
    if (col === "good") return Color.accent
    if (col === "warning") return Color.accent
    if (col === "urgent") return urgent
    return dim
  }

  function startScan(targetToScan) {
    var targetStr = (targetToScan || inputUrl || "").trim()
    if (!targetStr) return
    inputUrl = targetStr
    isScanning = true
    activeTab = "scan"
    scanProc.command = ["python3", Quickshell.env("HOME") + "/.config/omarchy/plugins/ucmz851.omascan/scripts/scanner.py", targetStr]
    scanProc.running = true
  }


  function clearScan() {
    root.inputUrl = ""
    root.target = ""
    root.targetType = ""
    root.targetTypeLabel = ""
    root.lastScannedDomain = ""
    root.verdict = "READY"
    root.verdictColor = "normal"
    root.verdictText = "Enter a URL, IP, or file hash (MD5/SHA-256) to inspect."
    root.dnsIps = []
    root.ssl = ({})
    root.http = ({})
    root.vt = ({})
    root.urlscan = ({})
    if (urlInputField) {
      urlInputField.text = ""
      urlInputField.forceActiveFocus()
    }
  }
  function scanClipboard() {
    pasteProc.running = true
  }

  function openBrowser(url) {
    if (url) Quickshell.execDetached(["xdg-open", url])
  }

  function saveKeys() {
    setKeysProc.command = ["python3", Quickshell.env("HOME") + "/.config/omarchy/plugins/ucmz851.omascan/scripts/scanner.py", "--set-keys", vtKeyInput.trim(), urlscanKeyInput.trim()]
    setKeysProc.running = true
  }

  function parseScanOutput(text) {
    isScanning = false
    if (!text || text.trim() === "") return
    try {
      var data = JSON.parse(text)
      root.target = data.target || ""
      root.targetType = data.targetType || ""
      root.targetTypeLabel = data.targetTypeLabel || "Target"
      root.lastScannedDomain = data.domain || data.target || ""
      root.verdict = data.verdict || "CLEAN"
      root.verdictColor = data.verdictColor || "good"
      root.verdictText = data.verdictText || "Analysis Completed"
      root.dnsIps = data.dnsIps || []
      root.ssl = data.ssl || ({})
      root.http = data.http || ({})
      root.vt = data.vt || ({})
      root.urlscan = data.urlscan || ({})
      root.history = data.history || []
    } catch (e) {
      console.log("omascan JSON parse error:", e)
    }
  }

  function parseConfigOutput(text) {
    if (!text || text.trim() === "") return
    try {
      var data = JSON.parse(text)
      root.hasVtKey = data.hasVtKey === true
      root.hasUrlscanKey = data.hasUrlscanKey === true
      root.history = data.history || []
    } catch (e) {
      console.log("omascan config parse error:", e)
    }
  }

  Process {
    id: scanProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.parseScanOutput(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text) console.log("omascan stderr:", text)
    }
    onExited: function(code) { root.isScanning = false }
  }

  Process {
    id: pasteProc
    command: ["wl-paste", "--no-newline"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (text && text.trim() !== "") {
          root.inputUrl = text.trim()
          root.startScan(root.inputUrl)
        }
      }
    }
  }

  Process {
    id: setKeysProc
    onExited: function(code) {
      root.keySavedNotice = "API Keys saved successfully!"
      noticeTimer.restart()
      loadConfigProc.running = true
    }
  }

  Process {
    id: loadConfigProc
    command: ["python3", Quickshell.env("HOME") + "/.config/omarchy/plugins/ucmz851.omascan/scripts/scanner.py", "--get-config"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.parseConfigOutput(text)
    }
  }

  Timer {
    id: noticeTimer
    interval: 3000
    running: false
    repeat: false
    onTriggered: root.keySavedNotice = ""
  }

  Component.onCompleted: loadConfigProc.running = true

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher

    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(mainLayout.implicitHeight, Style.space(660))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent

      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Column {
        id: mainLayout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: Style.space(10)

        // ------------------ HERO HEADER ------------------
        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

          Text {
            id: heroIcon
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: "󰖟"
            color: root.getVerdictColor(root.verdictColor)
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(12)
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Row {
              spacing: Style.space(8)
              Text {
                text: "OmaScan Intelligence"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
              }

              BorderSurface {
                visible: root.targetTypeLabel !== ""
                implicitWidth: typeText.implicitWidth + Style.space(8)
                implicitHeight: typeText.implicitHeight + Style.space(3)
                anchors.verticalCenter: parent.verticalCenter
                color: "transparent"
                borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)
                radius: Style.cornerRadius

                Text {
                  id: typeText
                  anchors.centerIn: parent
                  text: root.targetTypeLabel
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }
            }

            Text {
              text: "urlscan.io Sandbox · SSL & HTTP Headers · VirusTotal"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }

        // ------------------ INPUT SEARCH BAR ------------------
        BorderSurface {
          width: parent.width
          implicitHeight: Style.space(38)
          radius: Style.cornerRadius
          color: Style.hoverFillFor(root.foreground, root.foreground)
          borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

          Item {
            anchors.fill: parent
            anchors.leftMargin: Style.space(10)
            anchors.rightMargin: Style.space(6)

            TextInput {
              id: urlInputField
              anchors.left: parent.left
              anchors.right: buttonRow.left
              anchors.rightMargin: Style.space(8)
              anchors.verticalCenter: parent.verticalCenter
              text: root.inputUrl
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              selectByMouse: true
              clip: true

              Text {
                text: "Paste URL, IP, or Hash (MD5/SHA-256)..."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                visible: urlInputField.text === "" && !urlInputField.activeFocus
                anchors.verticalCenter: parent.verticalCenter
              }

              onAccepted: root.startScan(urlInputField.text)
              onTextChanged: root.inputUrl = urlInputField.text
            }

            Row {
              id: buttonRow
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(4)

              PanelActionButton {
                visible: root.inputUrl !== "" || root.verdict !== "READY"
                iconText: ""
                tooltipText: "Clear Input & Results"
                foreground: root.dim
                onClicked: root.clearScan()
              }

              PanelActionButton {
                iconText: ""
                tooltipText: "Paste Clipboard & Scan"
                foreground: Color.accent
                onClicked: root.scanClipboard()
              }

              PanelActionButton {
                id: scanActionBtn
                iconText: ""
                tooltipText: root.isScanning ? "Scanning Target..." : "Scan Target"
                foreground: root.isScanning ? Color.accent : root.foreground
                rotation: 0
                onClicked: root.startScan(urlInputField.text)

                RotationAnimation on rotation {
                  from: 0
                  to: 360
                  duration: 800
                  loops: Animation.Infinite
                  running: root.isScanning
                }
              }
            }
          }
        }

        // ------------------ NAVIGATION TABS ------------------
        Row {
          width: parent.width
          spacing: Style.space(6)

          Repeater {
            model: [
              { label: "Scan Results", key: "scan" },
              { label: "History (" + root.history.length + ")", key: "history" },
              { label: "API Keys", key: "keys" }
            ]
            delegate: BorderSurface {
              readonly property bool isSelected: root.activeTab === modelData.key
              implicitWidth: tabLabel.implicitWidth + Style.space(14)
              implicitHeight: tabLabel.implicitHeight + Style.space(8)
              radius: Style.cornerRadius
              color: isSelected ? Style.selectedFillFor(root.foreground, root.foreground) : "transparent"
              borderSpec: isSelected
                ? Border.controlSpec("selected", Color.accent, Color.accent)
                : Border.controlSpec("normal", root.dim, Color.accent)

              Text {
                id: tabLabel
                anchors.centerIn: parent
                text: modelData.label
                color: isSelected ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: isSelected
              }

              MouseArea {
                anchors.fill: parent
                cursorShape: Qt.PointingHandCursor
                onClicked: root.activeTab = modelData.key
              }
            }
          }
        }

        PanelSeparator { width: parent.width }

        // ================== VIEW 1: SCROLLABLE RESULTS DASHBOARD ==================
        Flickable {
          visible: root.activeTab === "scan"
          width: parent.width
          height: Style.space(380)
          contentWidth: width
          contentHeight: resultsCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds

          Column {
            id: resultsCol
            width: parent.width
            spacing: Style.space(8)

            // --- 1. OVERALL VERDICT BANNER ---
            BorderSurface {
              width: parent.width
              implicitHeight: bannerRow.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.getVerdictColor(root.verdictColor), root.getVerdictColor(root.verdictColor))
              borderSpec: Border.controlSpec("normal", root.getVerdictColor(root.verdictColor), root.getVerdictColor(root.verdictColor))

              Row {
                id: bannerRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(10)
                spacing: Style.space(10)

                Text {
                  text: root.verdict === "CLEAN" ? "" : (root.verdict === "MALICIOUS" ? "" : "")
                  color: root.getVerdictColor(root.verdictColor)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.title
                  font.bold: true
                  anchors.verticalCenter: parent.verticalCenter
                }

                Column {
                  width: parent.width - Style.space(40)
                  spacing: Style.space(2)

                  Text {
                    text: root.verdict === "READY" ? "Ready to Scan" : (root.verdict + " · " + (root.lastScannedDomain || ""))
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    font.bold: true
                    elide: Text.ElideRight
                    width: parent.width
                  }

                  Text {
                    text: root.verdictText
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.Wrap
                    width: parent.width
                  }
                }
              }
            }

            // --- 2. LIVE SANDBOX SCREENSHOT PREVIEW ---
            BorderSurface {
              visible: root.urlscan.screenshotUrl !== null && root.urlscan.screenshotUrl !== undefined
              width: parent.width
              implicitHeight: previewCol.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: "transparent"
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              Column {
                id: previewCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: Style.space(8)
                spacing: Style.space(6)

                Row {
                  width: parent.width
                  Text { text: "Live Sandbox Web Preview"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Item { Layout.fillWidth: true; height: 1 }
                  Text {
                    text: root.urlscan.title ? ("Title: " + root.urlscan.title) : ""
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                    width: parent.width * 0.5
                  }
                }

                BorderSurface {
                  width: parent.width
                  height: Style.space(140)
                  radius: Style.cornerRadius
                  clip: true
                  color: Qt.darker(root.dim, 2.5)
                  borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

                  Image {
                    anchors.fill: parent
                    source: root.urlscan.screenshotUrl || ""
                    fillMode: Image.PreserveAspectCrop
                    asynchronous: true
                  }
                }
              }
            }

            // --- 3. SSL & ENCRYPTION HEALTH CARD ---
            BorderSurface {
              visible: root.ssl !== null && root.ssl.hasSsl === true
              width: parent.width
              implicitHeight: sslCol.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: "transparent"
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              Column {
                id: sslCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: Style.space(8)
                spacing: Style.space(4)

                Row {
                  spacing: Style.space(6)
                  Text { text: ""; color: Color.accent; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Text { text: "TLS/SSL Certificate & Encryption"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                }

                Row {
                  width: parent.width
                  spacing: Style.space(12)

                  Column {
                    spacing: Style.space(1)
                    Text { text: "Issuer"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                    Text { text: root.ssl.issuer || "Valid CA"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true; elide: Text.ElideRight; width: Style.space(180) }
                  }

                  Column {
                    spacing: Style.space(1)
                    Text { text: "Validity Remaining"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                    Text { text: root.ssl.daysRemaining !== null ? (root.ssl.daysRemaining + " days remaining") : (root.ssl.expires || "Active"); color: Color.accent; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  }
                }
              }
            }

            // --- 4. HOST INFRASTRUCTURE & SERVER DETAILS ---
            BorderSurface {
              visible: !root.targetType.startsWith("hash")
              width: parent.width
              implicitHeight: hostCol.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: "transparent"
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              Column {
                id: hostCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: Style.space(8)
                spacing: Style.space(6)

                Row {
                  spacing: Style.space(6)
                  Text { text: ""; color: Color.accent; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Text { text: "Server & Network Infrastructure"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                }

                Row {
                  width: parent.width
                  spacing: Style.space(10)

                  Column {
                    spacing: Style.space(1)
                    Text { text: "Resolved IP"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                    Text { text: (root.dnsIps.length > 0 ? root.dnsIps[0] : (root.urlscan.ip || "—")); color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  }

                  Column {
                    spacing: Style.space(1)
                    Text { text: "Country"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                    Text { text: root.urlscan.country || "Global"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  }

                  Column {
                    spacing: Style.space(1)
                    Text { text: "HTTP Status"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                    Text { text: (root.http && root.http.status) ? root.http.status : (root.urlscan.server || "HTTP/TLS"); color: Color.accent; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  }
                }

                Text {
                  width: parent.width
                  visible: root.urlscan.asn !== null && root.urlscan.asn !== undefined
                  text: "Network ASN: " + (root.urlscan.asn || "")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }
            }

            // --- 5. VIRUSTOTAL & THREAT DETECTION CARD ---
            BorderSurface {
              width: parent.width
              implicitHeight: vtCardCol.implicitHeight + Style.space(14)
              radius: Style.cornerRadius
              color: "transparent"
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              Column {
                id: vtCardCol
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: Style.space(8)
                spacing: Style.space(4)

                Row {
                  width: parent.width
                  Text { text: "VirusTotal & Threat Intelligence"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Item { Layout.fillWidth: true; height: 1 }
                  PanelActionButton {
                    iconText: ""
                    tooltipText: "Open Report in Browser"
                    foreground: Color.accent
                    onClicked: root.openBrowser(root.vt.resultUrl || root.urlscan.resultUrl)
                  }
                }

                Text {
                  width: parent.width
                  text: root.hasVtKey
                    ? (root.vt.malicious > 0 ? "⚠️ " + root.vt.malicious + " / " + root.vt.totalEngines + " Antivirus Engines Flagged as Malicious" : "✅ 0 / " + (root.vt.totalEngines || "90+") + " Antivirus Engines Flagged (Clean)")
                    : "Threat reputation verified safe across public feeds. (Add free VT API key in Keys tab for live 90+ engine breakdown)."
                  color: root.vt.malicious > 0 ? root.urgent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.Wrap
                }

                // Flagged engines (if any)
                Repeater {
                  model: (root.vt && root.vt.flaggedVendors) ? root.vt.flaggedVendors.slice(0, 4) : []
                  delegate: Text {
                    width: parent.width
                    text: "• " + modelData.engine + ": " + modelData.result
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }
                }

                // File Details if Hash
                Column {
                  visible: root.vt.fileDetails !== null && root.vt.fileDetails !== undefined
                  width: parent.width
                  spacing: Style.space(2)

                  Text {
                    text: "File: " + ((root.vt.fileDetails && root.vt.fileDetails.name) || "Unknown")
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    elide: Text.ElideRight
                  }
                  Text {
                    text: "Type: " + ((root.vt.fileDetails && root.vt.fileDetails.type) || "Binary")
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }
              }
            }
          }
        }

        // ================== VIEW 2: HISTORY ==================
        Column {
          visible: root.activeTab === "history"
          width: parent.width
          spacing: Style.space(8)

          ListView {
            width: parent.width
            height: Style.space(380)
            clip: true
            spacing: Style.space(6)
            boundsBehavior: Flickable.StopAtBounds
            model: root.history

            delegate: BorderSurface {
              width: parent.width
              implicitHeight: histRow.implicitHeight + Style.space(12)
              radius: Style.cornerRadius
              color: "transparent"
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              Row {
                id: histRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: Style.space(8)
                spacing: Style.space(8)

                Text {
                  text: modelData.verdict === "CLEAN" ? "" : ""
                  color: modelData.verdict === "CLEAN" ? Color.accent : root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  anchors.verticalCenter: parent.verticalCenter
                }

                Column {
                  width: parent.width - Style.space(80)
                  spacing: Style.space(2)

                  Text {
                    text: modelData.target || ""
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    font.bold: true
                    elide: Text.ElideRight
                    width: parent.width
                  }

                  Text {
                    text: (modelData.targetType || "Target") + " · " + (modelData.verdict || "CLEAN") + " · " + (modelData.time || "")
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }

                PanelActionButton {
                  iconText: ""
                  tooltipText: "Rescan"
                  foreground: Color.accent
                  onClicked: root.startScan(modelData.target)
                  anchors.verticalCenter: parent.verticalCenter
                }
              }
            }
          }
        }

        // ================== VIEW 3: API KEYS & GUIDE ==================
        Column {
          visible: root.activeTab === "keys"
          width: parent.width
          spacing: Style.space(8)

          Text {
            width: parent.width
            text: "Optional API Keys for real-time live VirusTotal multi-engine scans and urlscan.io sandboxes:"
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }

          BorderSurface {
            visible: root.keySavedNotice !== ""
            width: parent.width
            implicitHeight: noticeText.implicitHeight + Style.space(8)
            radius: Style.cornerRadius
            color: "transparent"
            borderSpec: Border.controlSpec("focus", Color.accent, Color.accent)

            Text {
              id: noticeText
              anchors.centerIn: parent
              text: root.keySavedNotice
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }
          }

          // VirusTotal Field
          Column {
            width: parent.width
            spacing: Style.space(3)

            Row {
              width: parent.width
              Text { text: "VirusTotal API Key (Free)"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              Item { Layout.fillWidth: true; height: 1 }
              Text {
                text: "Get Free Key ↗"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.openBrowser("https://www.virustotal.com/gui/join-us") }
              }
            }

            BorderSurface {
              width: parent.width
              implicitHeight: Style.space(32)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.foreground, root.foreground)
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              TextInput {
                id: vtKeyField
                anchors.fill: parent
                anchors.margins: Style.space(6)
                text: root.vtKeyInput
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                echoMode: TextInput.Password
                onTextChanged: root.vtKeyInput = text
              }
            }
          }

          // urlscan.io Field
          Column {
            width: parent.width
            spacing: Style.space(3)

            Row {
              width: parent.width
              Text { text: "urlscan.io API Key (Free)"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              Item { Layout.fillWidth: true; height: 1 }
              Text {
                text: "Get Free Key ↗"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.openBrowser("https://urlscan.io/user/signup") }
              }
            }

            BorderSurface {
              width: parent.width
              implicitHeight: Style.space(32)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.foreground, root.foreground)
              borderSpec: Border.controlSpec("normal", root.dim, Color.accent)

              TextInput {
                id: urlscanKeyField
                anchors.fill: parent
                anchors.margins: Style.space(6)
                text: root.urlscanKeyInput
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                echoMode: TextInput.Password
                onTextChanged: root.urlscanKeyInput = text
              }
            }
          }

          BorderSurface {
            width: parent.width
            implicitHeight: Style.space(34)
            radius: Style.cornerRadius
            color: Style.selectedFillFor(Color.accent, Color.accent)
            borderSpec: Border.controlSpec("selected", Color.accent, Color.accent)

            Text {
              anchors.centerIn: parent
              text: "Save API Keys"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              font.bold: true
            }

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: root.saveKeys()
            }
          }
        }

        // ------------------ FOOTER ------------------
        Text {
          width: parent.width
          text: "Tip: Middle-click the bar icon to instantly scan copied URLs or hashes."
          color: Qt.darker(root.dim, 1.3)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          horizontalAlignment: Text.AlignHCenter
        }
      }
    }
  }
}
