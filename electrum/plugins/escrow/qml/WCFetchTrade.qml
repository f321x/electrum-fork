import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root

    title: qsTr('Fetch Trade')

    property var plugin: AppController.plugin('escrow')
    property var summary: null
    property bool fetching: false
    property string statusText: ''
    property bool failed: false

    valid: summary != null

    function apply() {
        wizard_data['trade_summary'] = summary
    }

    function fetchTrade() {
        var code = codeEdit.text.trim()
        if (code == '')
            return
        fetching = true
        failed = false
        statusText = qsTr('Fetching trade details...')
        plugin.fetchTrade(code)
    }

    Connections {
        target: plugin
        function onTradeFetched(tradeSummary) {
            summary = tradeSummary
            fetching = false
            statusText = qsTr('Trade found! Click Next to review the details.')
        }
        function onTradeFetchFailed(message) {
            fetching = false
            failed = true
            statusText = message
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip: true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width

            RowLayout {
                Label {
                    text: qsTr('Trade Code')
                    color: Material.accentColor
                }
                HelpButton {
                    heading: qsTr('Trade Code')
                    helptext: qsTr('Enter the trade code you received from the trade maker.')
                }
            }

            RowLayout {
                Layout.fillWidth: true

                TextField {
                    id: codeEdit
                    Layout.fillWidth: true
                    placeholderText: 'trade1...'
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                    enabled: !fetching
                    onTextChanged: {
                        // entering a different code invalidates the fetched trade
                        summary = null
                        failed = false
                        statusText = ''
                    }
                }

                ToolButton {
                    icon.source: Qt.resolvedUrl('../../../gui/icons/paste.png')
                    icon.color: 'transparent'
                    enabled: codeEdit.enabled
                    onClicked: codeEdit.text = AppController.clipboardToText()
                }

                ToolButton {
                    icon.source: Qt.resolvedUrl('../../../gui/icons/qrcode.png')
                    icon.color: 'transparent'
                    enabled: codeEdit.enabled
                    onClicked: {
                        var scanner = app.scanDialog.createObject(app, {
                            hint: qsTr('Scan the trade code you received from the trade maker')
                        })
                        scanner.onFoundText.connect(function(data) {
                            codeEdit.text = data
                            scanner.close()
                        })
                        scanner.open()
                    }
                }
            }

            FlatButton {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr('Fetch Trade Details')
                icon.source: Qt.resolvedUrl('../../../gui/icons/update.png')
                enabled: codeEdit.text.trim() != '' && !fetching
                onClicked: fetchTrade()
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: statusText != ''
                iconStyle: fetching
                    ? InfoTextArea.IconStyle.Spinner
                    : failed ? InfoTextArea.IconStyle.Error : InfoTextArea.IconStyle.Done
                text: statusText
            }
        }
    }
}
