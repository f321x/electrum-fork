import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    id: root

    title: qsTr('Create Trade')

    property var plugin: AppController.plugin('escrow')
    property string warningText: ''

    valid: titleEdit.text.trim() != ''
        && contractEdit.text.trim() != ''
        && amountSat() >= plugin.minTradeAmountSat
        && warningText == ''

    function amountSat() {
        return amountBtc.textAsSats ? amountBtc.textAsSats.satsInt : 0
    }

    function bondSat() {
        return Math.floor(bondPercentage.value * amountSat() / 100)
    }

    function revalidate() {
        warningText = plugin.validateTradeParams({
            'trade_amount_sat': amountSat(),
            'bond_sat': bondSat(),
            'payment_direction': directionComboBox.currentIndex
        })
    }

    function apply() {
        wizard_data['title'] = titleEdit.text.trim()
        wizard_data['contract_text'] = contractEdit.text.trim()
        wizard_data['trade_amount_sat'] = amountSat()
        wizard_data['bond_sat'] = bondSat()
        wizard_data['payment_direction'] = directionComboBox.currentIndex
    }

    Connections {
        target: plugin
        function onChannelsUpdated() {
            revalidate()
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip: true
        interactive: height < contentHeight

        GridLayout {
            id: mainLayout
            width: parent.width
            columns: 2

            Label {
                text: qsTr('Title')
                color: Material.accentColor
            }

            TextField {
                id: titleEdit
                Layout.fillWidth: true
                maximumLength: plugin.titleMaxLength
                placeholderText: qsTr('Enter a short trade description...')
            }

            RowLayout {
                Layout.columnSpan: 2
                Label {
                    text: qsTr('Contract')
                    color: Material.accentColor
                }
                HelpButton {
                    heading: qsTr('Contract')
                    helptext: qsTr('Specify the conditions of the trade as detailed as possible. In case of a conflict the escrow agent will decide the trade outcome based on this contract.')
                }
            }

            ElTextArea {
                id: contractEdit
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.minimumHeight: 120
                wrapMode: TextEdit.Wrap
                placeholderText: qsTr('Enter contract details (max %1 characters)...').arg(plugin.contractMaxLength)
                onTextChanged: {
                    if (text.length > plugin.contractMaxLength) {
                        text = text.substring(0, plugin.contractMaxLength)
                        cursorPosition = text.length
                    }
                }
            }

            ElComboBox {
                id: directionComboBox
                model: [qsTr('I send'), qsTr('I receive')]
                onCurrentIndexChanged: revalidate()
            }

            RowLayout {
                Layout.fillWidth: true

                BtcField {
                    id: amountBtc
                    Layout.fillWidth: true
                    fiatfield: amountFiat
                    onTextAsSatsChanged: revalidate()
                }

                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Item { visible: Daemon.fx.enabled; width: 1; height: 1 }

            RowLayout {
                Layout.fillWidth: true
                visible: Daemon.fx.enabled

                FiatField {
                    id: amountFiat
                    Layout.fillWidth: true
                    btcfield: amountBtc
                }

                Label {
                    text: Daemon.fx.fiatCurrency
                    color: Material.accentColor
                }
            }

            RowLayout {
                Label {
                    text: qsTr('Bond')
                    color: Material.accentColor
                }
                HelpButton {
                    heading: qsTr('Bond Amount')
                    helptext: qsTr('Percentage of the trade amount that the trade participant which receives the main trade payment will lock to the escrow agent. This ensures both participants have something to lose (skin-in-the-game). The bond will get refunded in case of a successful trade.')
                }
            }

            RowLayout {
                SpinBox {
                    id: bondPercentage
                    from: 0
                    to: 100
                    value: 3
                    onValueChanged: revalidate()
                }
                Label {
                    text: '%'
                    color: Material.accentColor
                }
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingMedium
                visible: warningText != ''
                iconStyle: InfoTextArea.IconStyle.Warn
                text: warningText
            }
        }
    }
}
