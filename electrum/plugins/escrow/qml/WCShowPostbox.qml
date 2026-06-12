import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root

    title: qsTr('Trade Postbox')

    property var plugin: AppController.plugin('escrow')
    property string postboxKey: ''
    property string errorText: ''

    valid: postboxKey != ''
    last: true

    function apply() { }

    Component.onCompleted: {
        plugin.createPostbox()
    }

    Connections {
        target: plugin
        function onPostboxCreated(key) {
            postboxKey = key
        }
        function onPostboxFailed(message) {
            errorText = qsTr('Error creating postbox: %1').arg(message)
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
                visible: postboxKey == '' && errorText == ''
                iconStyle: InfoTextArea.IconStyle.Spinner
                text: qsTr('Creating postbox...')
            }

            InfoTextArea {
                Layout.fillWidth: true
                visible: errorText != ''
                iconStyle: InfoTextArea.IconStyle.Error
                text: errorText
            }

            Label {
                visible: postboxKey != ''
                text: qsTr('Trade Postbox Key')
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.fillWidth: true
                visible: postboxKey != ''

                Label {
                    width: parent.width
                    text: postboxKey
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                    wrapMode: Text.WrapAnywhere
                }
            }

            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                visible: postboxKey != ''

                FlatButton {
                    text: qsTr('Copy')
                    icon.source: Qt.resolvedUrl('../../../gui/icons/copy_bw.png')
                    onClicked: {
                        AppController.textToClipboard(postboxKey)
                        toaster.show(this, qsTr('Copied!'))
                    }
                }

                FlatButton {
                    text: qsTr('Share')
                    icon.source: Qt.resolvedUrl('../../../gui/icons/share.png')
                    onClicked: {
                        var dialog = app.genericShareDialog.createObject(app, {
                            title: qsTr('Trade Postbox Key'),
                            text: postboxKey
                        })
                        dialog.open()
                    }
                }
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: postboxKey != ''
                iconStyle: InfoTextArea.IconStyle.Info
                text: qsTr('Send this key to your trading partner over a secure channel. '
                    + 'Anyone with this key can see the trade contract and accept the trade.')
            }
        }
    }

    Toaster {
        id: toaster
    }
}
