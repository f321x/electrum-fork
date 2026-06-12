import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/controls"

ElDialog {
    id: dialog

    required property string tradeId
    required property var details
    property var plugin: AppController.plugin('escrow')

    signal resolved

    title: qsTr('Resolve Mediation')
    iconSource: Qt.resolvedUrl('../escrow-icon.png')

    anchors.centerIn: parent
    width: parent.width * 0.95

    function makerSat() {
        return makerAmount.textAsSats ? makerAmount.textAsSats.satsInt : 0
    }

    function takerSat() {
        return takerAmount.textAsSats ? takerAmount.textAsSats.satsInt : 0
    }

    property bool overspent: makerSat() + takerSat() > details.potSat
    property var remainingSat: details.potSat - makerSat() - takerSat()

    Component.onCompleted: {
        makerAmount.text = details.makerDefaultSat > 0
            ? Config.formatSatsForEditing(details.makerDefaultSat) : ''
        takerAmount.text = details.takerDefaultSat > 0
            ? Config.formatSatsForEditing(details.takerDefaultSat) : ''
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true
            text: qsTr("Decide how the locked funds get distributed between the participants. "
                + "Funds you don't distribute remain with you (your mediation fee).")
            wrapMode: Text.Wrap
        }

        Label {
            text: qsTr('Locked funds (pot): %1').arg(details.potText)
            color: Material.accentColor
        }

        GridLayout {
            Layout.fillWidth: true
            columns: 3

            Label {
                text: qsTr('Maker payout (%1):').arg(details.makerRoleText)
            }

            BtcField {
                id: makerAmount
                Layout.fillWidth: true
                fiatfield: makerAmountFiat
            }

            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }

            // hidden fiat companions, BtcField requires them
            FiatField {
                id: makerAmountFiat
                visible: false
                btcfield: makerAmount
            }

            Label {
                text: qsTr('Taker payout (%1):').arg(details.takerRoleText)
            }

            BtcField {
                id: takerAmount
                Layout.fillWidth: true
                fiatfield: takerAmountFiat
            }

            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }

            FiatField {
                id: takerAmountFiat
                visible: false
                btcfield: takerAmount
            }
        }

        InfoTextArea {
            Layout.fillWidth: true
            visible: overspent
            iconStyle: InfoTextArea.IconStyle.Error
            text: qsTr('The payouts exceed the locked funds.')
        }

        Label {
            Layout.fillWidth: true
            visible: !overspent && remainingSat > 0
            text: qsTr('You keep %1 as mediation fee.').arg(Config.formatSats(remainingSat, true))
            color: constants.mutedForeground
            wrapMode: Text.Wrap
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Resolve')
            icon.source: Qt.resolvedUrl('../../../gui/icons/confirmed.png')
            enabled: !overspent
            onClicked: {
                var confirmdialog = app.messageDialog.createObject(app, {
                    text: qsTr('Resolve the mediation with a payout of %1 to the maker and %2 to the taker?')
                        .arg(Config.formatSats(makerSat(), true))
                        .arg(Config.formatSats(takerSat(), true)),
                    yesno: true
                })
                confirmdialog.accepted.connect(function() {
                    var error = plugin.resolveMediation(dialog.tradeId, makerSat(), takerSat())
                    if (error != '') {
                        var msgdialog = app.messageDialog.createObject(app, {
                            title: qsTr('Error'),
                            iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
                            text: error
                        })
                        msgdialog.open()
                        return
                    }
                    var donedialog = app.messageDialog.createObject(app, {
                        text: qsTr('Mediation resolved. The participants have been notified and their payouts will be paid out.')
                    })
                    donedialog.open()
                    dialog.resolved()
                    dialog.doAccept()
                })
                confirmdialog.open()
            }
        }
    }
}
