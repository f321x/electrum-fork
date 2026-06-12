import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root

    title: qsTr('Accept Trade')

    property var plugin: AppController.plugin('escrow')
    property var summary: wizard_data['trade_summary']
    property bool accepting: false
    property string errorText: ''

    valid: false

    function apply() { }

    Connections {
        target: plugin
        function onTradeAccepted() {
            accepting = false
            var dialog = app.messageDialog.createObject(app, {
                text: qsTr('Trade accepted and funded successfully!')
            })
            dialog.closed.connect(function() {
                wizard.doAccept()
            })
            dialog.open()
        }
        function onTradeAcceptFailed(message) {
            accepting = false
            errorText = message
        }
        function onPaymentAuthRejected() {
            accepting = false
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

            TextHighlightPane {
                Layout.fillWidth: true

                GridLayout {
                    width: parent.width
                    columns: 2

                    Label {
                        text: qsTr('Title') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: summary ? summary.title : ''
                        // counterparty-controlled string, never render as rich text
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                    }

                    Label {
                        text: qsTr('Trade amount') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: summary ? summary.amountText : ''
                    }

                    Label {
                        text: qsTr('Bond') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: summary ? summary.bondText : ''
                    }

                    Label {
                        text: qsTr('Agent fee') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: summary ? summary.feeText : ''
                    }

                    Label {
                        Layout.columnSpan: 2
                        text: qsTr('Escrow agent') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        text: summary ? summary.agentPubkey : ''
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeXSmall
                        wrapMode: Text.WrapAnywhere
                    }
                }
            }

            Label {
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Contract')
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.fillWidth: true

                Label {
                    width: parent.width
                    text: summary ? summary.contractText : ''
                    // counterparty-controlled string, never render as rich text
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                }
            }

            Label {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingSmall
                text: summary ? summary.narrative : ''
                wrapMode: Text.Wrap
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                iconStyle: InfoTextArea.IconStyle.Warn
                text: qsTr('The escrow agent is fully trusted and can take the locked funds. '
                    + 'Only accept this trade if you trust the escrow agent above.')
            }

            FlatButton {
                Layout.alignment: Qt.AlignHCenter
                enabled: !accepting
                text: summary != null && summary.hasPayment
                    ? qsTr('Accept and Pay %1').arg(summary.amountToPayText)
                    : qsTr('Accept Trade')
                icon.source: Qt.resolvedUrl('../../../gui/icons/confirmed.png')
                onClicked: {
                    accepting = true
                    errorText = ''
                    plugin.acceptTrade()
                }
            }

            BusyIndicator {
                Layout.alignment: Qt.AlignHCenter
                visible: accepting
                running: visible
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: errorText != ''
                iconStyle: InfoTextArea.IconStyle.Error
                text: errorText
            }
        }
    }
}
