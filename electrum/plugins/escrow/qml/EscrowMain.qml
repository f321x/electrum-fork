import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/controls"

Pane {
    id: root
    objectName: 'EscrowMain'

    padding: 0

    property var plugin: AppController.plugin('escrow')
    property bool pluginLoaded: false

    Component.onCompleted: {
        pluginLoaded = plugin.load(Daemon.currentWallet)
    }

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        ColumnLayout {
            Layout.preferredWidth: parent.width
            Layout.topMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            Heading {
                text: qsTr('Trade Escrow')
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: !root.pluginLoaded
                iconStyle: InfoTextArea.IconStyle.Error
                text: qsTr('The escrow plugin could not load this wallet. Make sure you are connected to a network.')
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: root.pluginLoaded && plugin.notificationText != ''
                iconStyle: plugin.notificationCritical
                    ? InfoTextArea.IconStyle.Warn
                    : InfoTextArea.IconStyle.Info
                text: plugin.notificationText
            }

            TextHighlightPane {
                Layout.fillWidth: true
                visible: root.pluginLoaded && plugin.isAgent

                // note: a Pane derives its content size only from a single child item,
                // so the tap handling must not be a second child item
                ColumnLayout {
                    width: parent.width
                    Label {
                        text: qsTr('Your agent public key')
                        font.pixelSize: constants.fontSizeSmall
                        color: Material.accentColor
                    }
                    Label {
                        Layout.fillWidth: true
                        text: plugin.agentPubkey
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                        wrapMode: Text.WrapAnywhere
                    }
                }

                TapHandler {
                    onTapped: {
                        var dialog = app.genericShareDialog.createObject(app, {
                            title: qsTr('Agent Public Key'),
                            text: plugin.agentPubkey,
                            text_help: qsTr('Share this public key with users so they use you as escrow agent.')
                        })
                        dialog.open()
                    }
                }
            }
        }

        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: constants.paddingLarge

            verticalPadding: bg.lineWidth
            horizontalPadding: 0
            background: PaneInsetBackground { id: bg; vertical: false }

            ElListView {
                id: listview
                anchors.fill: parent
                clip: true
                model: plugin.tradesModel

                delegate: ItemDelegate {
                    width: ListView.view.width
                    height: itemLayout.height

                    GridLayout {
                        id: itemLayout
                        columns: 2
                        rowSpacing: 0
                        anchors {
                            left: parent.left
                            right: parent.right
                            leftMargin: constants.paddingMedium
                            rightMargin: constants.paddingMedium
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.topMargin: constants.paddingSmall
                            text: model.title
                            // counterparty-controlled string, never render as rich text
                            textFormat: Text.PlainText
                            elide: Text.ElideRight
                            font.pixelSize: constants.fontSizeMedium
                            wrapMode: Text.Wrap
                            maximumLineCount: 2
                        }

                        Label {
                            Layout.topMargin: constants.paddingSmall
                            text: Config.formatSats(model.amount, true)
                            font.pixelSize: constants.fontSizeMedium
                            font.family: FixedFont
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.bottomMargin: constants.paddingSmall
                            text: model.date
                            font.pixelSize: constants.fontSizeSmall
                            color: constants.mutedForeground
                        }

                        Label {
                            Layout.bottomMargin: constants.paddingSmall
                            Layout.alignment: Qt.AlignRight
                            text: model.statetext
                            font.pixelSize: constants.fontSizeSmall
                            color: Material.accentColor
                        }
                    }

                    onClicked: {
                        var dialog = tradeDetailsDialog.createObject(root, {
                            tradeId: model.tradeid
                        })
                        dialog.open()
                    }
                }

                ScrollIndicator.vertical: ScrollIndicator { }

                Label {
                    visible: root.pluginLoaded && listview.model.count == 0
                    anchors.centerIn: parent
                    width: listview.width * 4/5
                    font.pixelSize: constants.fontSizeXXLarge
                    color: constants.mutedForeground
                    text: qsTr('No trades yet in this wallet')
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                }

                BusyIndicator {
                    anchors.centerIn: parent
                    visible: plugin.busy
                    running: visible
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: root.pluginLoaded && !plugin.isAgent
                enabled: plugin.canTrade
                text: qsTr('Create Trade')
                icon.source: Qt.resolvedUrl('../../../gui/icons/add.png')
                onClicked: {
                    var dialog = wizardDialog.createObject(app, { take: false })
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: root.pluginLoaded && !plugin.isAgent
                enabled: plugin.canTrade
                text: qsTr('Take Trade')
                icon.source: Qt.resolvedUrl('../../../gui/icons/tab_receive.png')
                onClicked: {
                    var dialog = wizardDialog.createObject(app, { take: true })
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: root.pluginLoaded && plugin.isAgent
                text: qsTr('Edit Profile')
                icon.source: Qt.resolvedUrl('../../../gui/icons/pen.png')
                onClicked: {
                    var dialog = profileDialog.createObject(root)
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Options')
                icon.source: Qt.resolvedUrl('../../../gui/icons/preferences.png')
                onClicked: optionsMenu.open()

                Menu {
                    id: optionsMenu
                    MenuItem {
                        text: qsTr('Escrow Agent Mode')
                        checkable: true
                        visible: plugin.canTrade
                        height: visible ? implicitHeight : 0
                        checked: plugin.agentModeEnabled
                        onTriggered: {
                            var error = plugin.setAgentMode(!plugin.agentModeEnabled)
                            if (error != '') {
                                var dialog = app.messageDialog.createObject(app, {
                                    title: qsTr('Error'),
                                    iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
                                    text: error
                                })
                                dialog.open()
                            }
                            // user interaction broke the declarative binding, restore it
                            checked = Qt.binding(function() { return plugin.agentModeEnabled })
                        }
                    }
                    MenuItem {
                        text: qsTr('Restore from Nostr Backup')
                        onTriggered: {
                            var dialog = app.messageDialog.createObject(app, {
                                title: qsTr('Restore from Nostr Backup'),
                                text: qsTr('Recover the trades of this wallet from the encrypted backup the plugin keeps on your Nostr relays, e.g. after restoring the wallet from seed.')
                                    + '\n\n' + qsTr('Search for a backup now?'),
                                yesno: true
                            })
                            dialog.accepted.connect(function() {
                                plugin.restoreBackup()
                            })
                            dialog.open()
                        }
                    }
                    MenuItem {
                        text: qsTr('Help')
                        onTriggered: {
                            var dialog = app.messageDialog.createObject(app, {
                                title: qsTr('Trade Escrow'),
                                text: plugin.helpText
                            })
                            dialog.open()
                        }
                    }
                }
            }
        }
    }

    property color navigationBarBackgroundColor: constants.highlightBackground

    Connections {
        target: plugin
        function onBackupRestoreDone(numRestored) {
            var text = numRestored > 0
                ? qsTr('Restored %1 trades from your Nostr relays.').arg(numRestored)
                : qsTr('Found a backup, but it contains no trades that are not already in this wallet.')
            var dialog = app.messageDialog.createObject(app, { text: text })
            dialog.open()
        }
        function onBackupRestoreFailed(message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
                text: message
            })
            dialog.open()
        }
    }

    Component {
        id: wizardDialog
        EscrowWizardDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: tradeDetailsDialog
        TradeDetailsDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: profileDialog
        AgentProfileDialog {
            onClosed: destroy()
        }
    }
}
