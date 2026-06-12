import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root

    title: qsTr('Escrow Agent')

    property var plugin: AppController.plugin('escrow')
    property var agents: []
    property var selectedAgent: null
    property string avatarSource: ''
    property string requestedAvatarUrl: ''

    valid: selectedAgent != null && selectedAgent.hasInfo

    function apply() {
        wizard_data['escrow_agent_pubkey'] = selectedAgent ? selectedAgent.pubkey : ''
        wizard_data['agent_fee_ppm'] = selectedAgent ? selectedAgent.feePpm : 0
    }

    function refresh() {
        var newAgents = plugin.getAgents()
        if (JSON.stringify(newAgents) == JSON.stringify(agents))
            return  // don't churn the combobox model while the user interacts with it
        var currentPubkey = selectedAgent ? selectedAgent.pubkey : ''
        agents = newAgents
        var index = -1
        for (var i = 0; i < agents.length; i++) {
            if (agents[i].pubkey == currentPubkey) {
                index = i
                break
            }
        }
        if (index < 0 && agents.length > 0)
            index = 0
        agentComboBox.model = agents
        agentComboBox.currentIndex = index
        updateSelection(index)
    }

    function updateSelection(index) {
        var agent = index >= 0 && index < agents.length ? agents[index] : null
        selectedAgent = agent
        var picture = agent ? agent.picture : ''
        if (picture == '') {
            avatarSource = ''
            requestedAvatarUrl = ''
        } else if (picture != requestedAvatarUrl) {
            // fetch each avatar url only once, a failed fetch is not retried
            avatarSource = ''
            requestedAvatarUrl = picture
            plugin.fetchAvatar(picture)
        }
    }

    Component.onCompleted: refresh()

    Timer {
        // agent profiles arrive over nostr in the background, keep the view fresh
        interval: 1000
        running: true
        repeat: true
        onTriggered: refresh()
    }

    Connections {
        target: plugin
        function onAvatarReceived(url, dataUrl) {
            if (requestedAvatarUrl == url)
                avatarSource = dataUrl
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

            Label {
                text: qsTr('Select trusted Escrow Agent')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true

                ElComboBox {
                    id: agentComboBox
                    Layout.fillWidth: true
                    textRole: 'name'
                    onActivated: (index) => updateSelection(index)
                }

                ToolButton {
                    icon.source: Qt.resolvedUrl('../../../gui/icons/add.png')
                    icon.color: 'transparent'
                    onClicked: {
                        var dialog = addAgentDialog.createObject(root)
                        dialog.open()
                    }
                }

                ToolButton {
                    icon.source: Qt.resolvedUrl('../../../gui/icons/delete.png')
                    icon.color: 'transparent'
                    enabled: selectedAgent != null
                    onClicked: {
                        plugin.deleteAgent(selectedAgent.pubkey)
                        selectedAgent = null
                        refresh()
                    }
                }
            }

            TextHighlightPane {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: selectedAgent != null

                RowLayout {
                    width: parent.width

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        visible: selectedAgent != null && selectedAgent.hasInfo

                        Label {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.name : ''
                            // remote-controlled strings must not be rendered as rich text
                            textFormat: Text.PlainText
                            font.bold: true
                            wrapMode: Text.Wrap
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.about : ''
                            textFormat: Text.PlainText
                            visible: text != ''
                            wrapMode: Text.Wrap
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.website : ''
                            textFormat: Text.PlainText
                            visible: text != ''
                            wrapMode: Text.WrapAnywhere
                            font.pixelSize: constants.fontSizeSmall
                        }

                        Label {
                            text: qsTr('Fee') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.feeText : ''
                        }

                        Label {
                            visible: selectedAgent != null && selectedAgent.inboundText != ''
                            text: qsTr('Inbound Liquidity') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            visible: selectedAgent != null && selectedAgent.inboundText != ''
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.inboundText : ''
                        }

                        Label {
                            visible: selectedAgent != null && selectedAgent.outboundText != ''
                            text: qsTr('Outbound Liquidity') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            visible: selectedAgent != null && selectedAgent.outboundText != ''
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.outboundText : ''
                        }

                        Label {
                            visible: selectedAgent != null && selectedAgent.lastSeenMinutes >= 0
                            text: qsTr('Last Seen') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            visible: selectedAgent != null && selectedAgent.lastSeenMinutes >= 0
                            Layout.fillWidth: true
                            text: selectedAgent
                                ? qsTr('%1 minutes ago').arg(selectedAgent.lastSeenMinutes)
                                : ''
                        }

                        Label {
                            visible: selectedAgent != null && selectedAgent.languagesText != ''
                            text: qsTr('Languages') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            visible: selectedAgent != null && selectedAgent.languagesText != ''
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.languagesText : ''
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                        }

                        Label {
                            visible: selectedAgent != null && selectedAgent.gpg != ''
                            text: qsTr('GPG') + ':'
                            color: Material.accentColor
                        }
                        Label {
                            visible: selectedAgent != null && selectedAgent.gpg != ''
                            Layout.fillWidth: true
                            text: selectedAgent ? selectedAgent.gpg : ''
                            textFormat: Text.PlainText
                            font.family: FixedFont
                            font.pixelSize: constants.fontSizeSmall
                            wrapMode: Text.WrapAnywhere
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            text: qsTr('Public key') + ': ' + (selectedAgent ? selectedAgent.pubkey : '')
                            font.family: FixedFont
                            font.pixelSize: constants.fontSizeXSmall
                            color: constants.mutedForeground
                            wrapMode: Text.WrapAnywhere
                        }
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: selectedAgent != null && !selectedAgent.hasInfo
                        text: qsTr('Fetching agent information...')
                        wrapMode: Text.Wrap
                    }

                    Image {
                        Layout.preferredWidth: constants.iconSizeXXLarge
                        Layout.preferredHeight: constants.iconSizeXXLarge
                        Layout.alignment: Qt.AlignTop
                        visible: avatarSource != ''
                        source: avatarSource
                        fillMode: Image.PreserveAspectFit
                    }
                }
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: selectedAgent != null && !selectedAgent.hasInfo
                iconStyle: InfoTextArea.IconStyle.Warn
                text: qsTr('No information available for this agent.')
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: selectedAgent != null && selectedAgent.hasInfo && selectedAgent.stale
                iconStyle: InfoTextArea.IconStyle.Warn
                text: qsTr("This agent hasn't been seen recently, it might be offline.")
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: agents.length == 0
                iconStyle: InfoTextArea.IconStyle.Info
                text: qsTr('Add the public key of an escrow agent both trade participants trust.')
            }
        }
    }

    Component {
        id: addAgentDialog
        ElDialog {
            id: dialog
            title: qsTr('Add Escrow Agent')
            anchors.centerIn: parent
            width: parent.width * 0.9

            onClosed: destroy()

            ColumnLayout {
                width: parent.width

                Label {
                    text: qsTr('Enter Escrow Agent Public Key:')
                }

                RowLayout {
                    Layout.fillWidth: true

                    TextField {
                        id: pubkeyEdit
                        Layout.fillWidth: true
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                    }

                    ToolButton {
                        icon.source: Qt.resolvedUrl('../../../gui/icons/paste.png')
                        icon.color: 'transparent'
                        onClicked: pubkeyEdit.text = AppController.clipboardToText()
                    }

                    ToolButton {
                        icon.source: Qt.resolvedUrl('../../../gui/icons/qrcode.png')
                        icon.color: 'transparent'
                        onClicked: {
                            var scanner = app.scanDialog.createObject(app, {
                                hint: qsTr('Scan the public key of the escrow agent')
                            })
                            scanner.onFoundText.connect(function(data) {
                                pubkeyEdit.text = data
                                scanner.close()
                            })
                            scanner.open()
                        }
                    }
                }

                FlatButton {
                    Layout.fillWidth: true
                    text: qsTr('Add')
                    enabled: pubkeyEdit.text.trim() != ''
                    onClicked: {
                        var error = plugin.addAgent(pubkeyEdit.text)
                        if (error != '') {
                            var msgdialog = app.messageDialog.createObject(app, {
                                title: qsTr('Error'),
                                iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
                                text: error
                            })
                            msgdialog.open()
                            return
                        }
                        var pubkey = pubkeyEdit.text.trim().toLowerCase()
                        dialog.close()
                        selectedAgent = null
                        refresh()
                        for (var i = 0; i < agents.length; i++) {
                            if (agents[i].pubkey == pubkey) {
                                agentComboBox.currentIndex = i
                                updateSelection(i)
                                break
                            }
                        }
                    }
                }
            }
        }
    }
}
