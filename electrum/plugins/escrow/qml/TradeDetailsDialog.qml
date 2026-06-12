import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/controls"

ElDialog {
    id: dialog

    required property string tradeId
    property var plugin: AppController.plugin('escrow')
    property var details: ({ 'found': false })
    property string statusText: ''
    // an action of this trade is in flight (gates the buttons against double taps)
    property bool actionPending: false

    title: qsTr('Trade Details')
    iconSource: Qt.resolvedUrl('../escrow-icon.png')

    width: parent.width
    height: parent.height
    padding: 0

    function refresh() {
        details = plugin.getTradeDetails(tradeId)
    }

    function showError(message) {
        var msgdialog = app.messageDialog.createObject(app, {
            title: qsTr('Error'),
            iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
            text: message
        })
        msgdialog.open()
    }

    Component.onCompleted: {
        refresh()
        if (details.found && details.autoSync) {
            statusText = qsTr('Syncing trade state with agent...')
            plugin.syncTrade(tradeId)
        }
    }

    Connections {
        target: plugin
        function onStateChanged() {
            // the trade can change remotely at any time (agent/counterparty updates)
            refresh()
        }
        function onTradeActionDone(tradeId, action, message) {
            if (tradeId != dialog.tradeId)
                return
            actionPending = false
            refresh()
            if (action == 'sync') {
                statusText = message
            } else {
                statusText = ''
                var msgdialog = app.messageDialog.createObject(app, { text: message })
                msgdialog.open()
            }
        }
        function onTradeActionFailed(tradeId, action, message) {
            if (tradeId != dialog.tradeId)
                return
            actionPending = false
            refresh()
            if (action == 'sync') {
                statusText = message
            } else {
                statusText = ''
                showError(message)
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            contentHeight: contentLayout.height
            clip: true
            interactive: height < contentHeight

            ColumnLayout {
                id: contentLayout
                width: parent.width

                GridLayout {
                    Layout.fillWidth: true
                    Layout.margins: constants.paddingLarge
                    columns: 2

                    Label {
                        text: qsTr('Title') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: details.title ? details.title : ''
                        // counterparty-controlled string, never render as rich text
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                    }

                    Label {
                        text: qsTr('State') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: details.stateText ? details.stateText : ''
                        font.bold: true
                    }

                    Label {
                        text: qsTr('Date') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: details.dateText ? details.dateText : ''
                    }

                    Label {
                        text: qsTr('Trade amount') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: details.amountText ? details.amountText : ''
                    }

                    Label {
                        text: qsTr('Bond') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: details.bondText ? details.bondText : ''
                    }

                    Label {
                        text: qsTr('Agent fee') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: details.feeText ? details.feeText : ''
                    }

                    Label {
                        visible: !details.isAgent
                        text: qsTr('Role') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        visible: !details.isAgent
                        Layout.fillWidth: true
                        text: details.roleText ? details.roleText : ''
                    }

                    Label {
                        visible: !details.isAgent
                        text: qsTr('Direction') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        visible: !details.isAgent
                        Layout.fillWidth: true
                        text: details.directionText ? details.directionText : ''
                        wrapMode: Text.Wrap
                    }

                    Label {
                        visible: details.payoutText !== undefined && details.payoutText != ''
                        text: qsTr('Your payout') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        visible: details.payoutText !== undefined && details.payoutText != ''
                        Layout.fillWidth: true
                        text: details.payoutText ? details.payoutText : ''
                    }

                    Label {
                        Layout.columnSpan: 2
                        text: qsTr('Trade ID') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        text: dialog.tradeId
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeXSmall
                        wrapMode: Text.WrapAnywhere
                    }

                    Label {
                        visible: !details.isAgent
                        Layout.columnSpan: 2
                        text: qsTr('Agent') + ':'
                        color: Material.accentColor
                    }
                    Label {
                        visible: !details.isAgent
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        text: details.agentPubkey ? details.agentPubkey : ''
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeXSmall
                        wrapMode: Text.WrapAnywhere
                    }
                }

                // participants (agent view)
                Repeater {
                    model: details.participants ? details.participants : []

                    TextHighlightPane {
                        Layout.fillWidth: true
                        Layout.leftMargin: constants.paddingLarge
                        Layout.rightMargin: constants.paddingLarge

                        ColumnLayout {
                            width: parent.width
                            Label {
                                text: modelData.roleText
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: modelData.pubkey
                                font.family: FixedFont
                                font.pixelSize: constants.fontSizeXSmall
                                wrapMode: Text.WrapAnywhere
                            }
                            Label {
                                Layout.fillWidth: true
                                text: modelData.statusText
                                wrapMode: Text.Wrap
                            }
                        }
                    }
                }

                InfoTextArea {
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingLarge
                    Layout.rightMargin: constants.paddingLarge
                    visible: details.mediationHint === true
                    iconStyle: InfoTextArea.IconStyle.Info
                    text: qsTr('The trade is in mediation. Contact the escrow agent out of band (see their profile) to provide your evidence.')
                }

                // postbox key with share option, while waiting for the taker
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingLarge
                    Layout.rightMargin: constants.paddingLarge
                    visible: details.showCopyPostbox === true

                    Label {
                        text: qsTr('Trade Postbox Key')
                        color: Material.accentColor
                    }

                    TextHighlightPane {
                        Layout.fillWidth: true

                        RowLayout {
                            width: parent.width

                            Label {
                                Layout.fillWidth: true
                                text: details.postboxKey ? details.postboxKey : ''
                                font.family: FixedFont
                                font.pixelSize: constants.fontSizeXSmall
                                wrapMode: Text.WrapAnywhere
                            }

                            ToolButton {
                                icon.source: Qt.resolvedUrl('../../../gui/icons/share.png')
                                icon.color: 'transparent'
                                onClicked: {
                                    var sharedialog = app.genericShareDialog.createObject(app, {
                                        title: qsTr('Trade Postbox Key'),
                                        text: details.postboxKey,
                                        text_help: qsTr('Send this key to your trading partner over a secure channel. Anyone with this key can see the trade contract and accept the trade.')
                                    })
                                    sharedialog.open()
                                }
                            }
                        }
                    }
                }

                Label {
                    Layout.leftMargin: constants.paddingLarge
                    text: qsTr('Contract')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.fillWidth: true
                    Layout.leftMargin: constants.paddingLarge
                    Layout.rightMargin: constants.paddingLarge

                    Label {
                        width: parent.width
                        text: details.contractText ? details.contractText : ''
                        // counterparty-controlled string, never render as rich text
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                    }
                }

                Label {
                    Layout.fillWidth: true
                    Layout.margins: constants.paddingLarge
                    visible: statusText != ''
                    text: statusText
                    color: constants.mutedForeground
                    wrapMode: Text.Wrap
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: details.showConfirm === true
                enabled: !actionPending
                text: qsTr('Confirm Success')
                icon.source: Qt.resolvedUrl('../../../gui/icons/confirmed.png')
                onClicked: {
                    var confirmdialog = app.messageDialog.createObject(app, {
                        text: details.confirmQuestion,
                        yesno: true
                    })
                    confirmdialog.accepted.connect(function() {
                        actionPending = true
                        plugin.confirmTrade(dialog.tradeId)
                    })
                    confirmdialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: details.showCancel === true
                enabled: !actionPending
                text: details.cancelLabel ? details.cancelLabel : qsTr('Cancel Trade')
                icon.source: Qt.resolvedUrl('../../../gui/icons/closebutton.png')
                onClicked: {
                    var confirmdialog = app.messageDialog.createObject(app, {
                        text: details.cancelQuestion,
                        yesno: true
                    })
                    confirmdialog.accepted.connect(function() {
                        actionPending = true
                        plugin.cancelTrade(dialog.tradeId)
                    })
                    confirmdialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: details.showMediate === true
                enabled: !actionPending
                text: qsTr('Mediation')
                icon.source: Qt.resolvedUrl('../../../gui/icons/info.png')
                onClicked: {
                    var confirmdialog = app.messageDialog.createObject(app, {
                        text: details.mediateQuestion,
                        yesno: true
                    })
                    confirmdialog.accepted.connect(function() {
                        actionPending = true
                        plugin.requestMediation(dialog.tradeId)
                    })
                    confirmdialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: details.showClaim === true
                enabled: !actionPending
                text: qsTr('Claim Payout')
                icon.source: Qt.resolvedUrl('../../../gui/icons/tab_receive.png')
                onClicked: {
                    actionPending = true
                    plugin.claimPayout(dialog.tradeId)
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: details.showResolve === true
                enabled: !actionPending
                text: qsTr('Resolve Mediation')
                icon.source: Qt.resolvedUrl('../../../gui/icons/pen.png')
                onClicked: {
                    var resolvedialog = resolveMediationDialog.createObject(dialog, {
                        tradeId: dialog.tradeId,
                        details: dialog.details
                    })
                    resolvedialog.resolved.connect(function() {
                        refresh()
                    })
                    resolvedialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: details.showSync === true
                enabled: !actionPending
                text: qsTr('Refresh')
                icon.source: Qt.resolvedUrl('../../../gui/icons/update.png')
                onClicked: {
                    actionPending = true
                    statusText = qsTr('Syncing trade state with agent...')
                    plugin.syncTrade(dialog.tradeId)
                }
            }
        }
    }

    Component {
        id: resolveMediationDialog
        ResolveMediationDialog {
            onClosed: destroy()
        }
    }
}
