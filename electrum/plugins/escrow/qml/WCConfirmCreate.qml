import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root

    title: qsTr('Confirm Trade Creation')

    property var plugin: AppController.plugin('escrow')
    property var summary: null
    property bool requesting: true
    property bool locking: false
    property bool locked: false
    property string errorText: ''

    valid: locked

    function apply() {
        wizard_data['trade_id'] = summary ? summary.tradeId : ''
    }

    Component.onCompleted: {
        // request the trade registration from the agent; params were collected
        // by the previous wizard pages
        plugin.registerTrade(wizard_data)
    }

    Connections {
        target: plugin
        function onTradeRegistered(tradeSummary) {
            summary = tradeSummary
            requesting = false
            errorText = ''
        }
        function onTradeRegisterFailed(message) {
            requesting = false
            errorText = qsTr('Error requesting escrow: %1').arg(message)
        }
        function onFundingDone() {
            locking = false
            locked = true
        }
        function onFundingFailed(message) {
            locking = false
            errorText = message
        }
        function onPaymentAuthRejected() {
            locking = false
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

            InfoTextArea {
                Layout.fillWidth: true
                visible: requesting
                iconStyle: InfoTextArea.IconStyle.Spinner
                text: qsTr('Requesting trade creation from agent...')
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: !requesting && !locked && errorText == '' && summary != null
                iconStyle: InfoTextArea.IconStyle.Info
                text: summary != null && summary.hasPayment
                    ? qsTr('Trade registered with agent. Please review and confirm to pay the funding invoice.')
                    : qsTr('Trade registered with agent. There is nothing to pay from your side.')
            }

            TextHighlightPane {
                Layout.fillWidth: true
                visible: summary != null

                GridLayout {
                    width: parent.width
                    columns: 2

                    Label {
                        text: qsTr('Trade ID') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: summary ? summary.tradeId : ''
                        // agent-controlled string, never render as rich text
                        textFormat: Text.PlainText
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                        wrapMode: Text.WrapAnywhere
                    }

                    Label {
                        text: qsTr('Agent') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: summary ? summary.agentPubkey.substring(0, 16) + '...' : ''
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
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
                        Layout.fillWidth: true
                        Layout.topMargin: constants.paddingSmall
                        text: summary ? summary.narrative : ''
                        wrapMode: Text.Wrap
                    }

                    Label {
                        visible: summary != null && summary.hasPayment
                        text: qsTr('Amount to pay now') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        visible: summary != null && summary.hasPayment
                        Layout.fillWidth: true
                        text: summary ? summary.amountToPayText : ''
                        font.bold: true
                    }
                }
            }

            FlatButton {
                Layout.alignment: Qt.AlignHCenter
                visible: summary != null && !locked
                enabled: !locking
                text: summary != null && summary.hasPayment ? qsTr('Lock Funding') : qsTr('Create Trade')
                icon.source: Qt.resolvedUrl('../../../gui/icons/lightning.png')
                onClicked: {
                    locking = true
                    errorText = ''
                    plugin.lockFunding()
                }
            }

            BusyIndicator {
                Layout.alignment: Qt.AlignHCenter
                visible: locking
                running: visible
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: locked
                iconStyle: InfoTextArea.IconStyle.Done
                text: qsTr('Trade created and funded successfully!')
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
