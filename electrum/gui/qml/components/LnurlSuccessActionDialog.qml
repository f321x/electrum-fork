import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Payment successful')
    iconSource: '../../icons/confirmed.png'

    property var actionData

    padding: 0
    needsSystemBarPadding: false

    ColumnLayout {
        width: parent.width
        spacing: 0

        ColumnLayout {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            spacing: constants.paddingMedium

            Label {
                visible: actionData.tag === 'message'
                Layout.fillWidth: true
                text: actionData.tag === 'message' ? actionData.message : ''
                wrapMode: Text.Wrap
            }

            Label {
                visible: actionData.tag === 'url'
                Layout.fillWidth: true
                text: actionData.tag === 'url' ? actionData.description : ''
                wrapMode: Text.Wrap
            }

            Label {
                visible: actionData.tag === 'url'
                Layout.fillWidth: true
                text: actionData.tag === 'url' ? actionData.url : ''
                color: Material.accentColor
                wrapMode: Text.WrapAnywhere
                font.pixelSize: constants.fontSizeSmall
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true
            FlatButton {
                visible: actionData.tag === 'url'
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Open')
                icon.source: '../../icons/link.png'
                onClicked: {
                    Qt.openUrlExternally(actionData.url)
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Close')
                onClicked: dialog.close()
            }
        }
    }
}
