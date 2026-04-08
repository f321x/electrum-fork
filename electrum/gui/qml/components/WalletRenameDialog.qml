import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr("Rename Wallet")
    iconSource: Qt.resolvedUrl('../../icons/pen.png')

    property string currentName

    signal nameChosen(string newName)

    anchors.centerIn: parent
    width: parent.width * 4/5
    padding: 0
    needsSystemBarPadding: false

    ColumnLayout {
        id: rootLayout
        width: parent.width
        spacing: 0

        ColumnLayout {
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge
            Layout.bottomMargin: constants.paddingLarge

            Label {
                Layout.fillWidth: true
                text: qsTr('Enter new wallet name')
                color: Material.accentColor
            }

            TextField {
                id: walletNameField
                Layout.fillWidth: true
                text: dialog.currentName
                focus: true
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                textUnderIcon: false
                text: qsTr('Ok')
                icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
                enabled: walletNameField.text !== dialog.currentName
                         && Daemon.isValidWalletName(walletNameField.text)
                onClicked: {
                    dialog.nameChosen(walletNameField.text)
                }
            }
        }
    }
}
