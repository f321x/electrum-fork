import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

Item {
    // route payment auth/confirmation requests from the escrow bridge
    // through the app-wide auth flow (biometrics/password/confirm dialog)
    Connections {
        target: AppController ? AppController.plugin('escrow') : null
        function onAuthRequired(method, authMessage) {
            app.handleAuthRequired(AppController.plugin('escrow'), method, authMessage)
        }
    }

    // entry in the wallet menu (top-left), harvested by WalletMainView.qml
    property variant wallet_menu_item: Component {
        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: Qt.resolvedUrl('../escrow-icon.png')
            action: Action {
                text: qsTr('Trade Escrow')
                enabled: app.stack.currentItem.objectName != 'EscrowMain'
                onTriggered: {
                    app.stack.pushOnRoot(Qt.resolvedUrl('EscrowMain.qml'))
                }
            }
        }
    }
}
