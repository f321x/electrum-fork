import QtQuick

import org.electrum

import "../../../gui/qml/components/wizard"

Wizard {
    id: escrowwizard

    // false: create a new trade (maker), true: take an existing trade (taker)
    property bool take: false

    wizardTitle: qsTr('Trade Escrow')
    iconSource: Qt.resolvedUrl('../escrow-icon.png')

    wiz: AppController.plugin('escrow').wizard

    Component.onCompleted: {
        var view = wiz.startWizardFrom(take ? 'fetch_trade' : 'create_trade')
        _loadNextComponent(view)
    }

    onClosed: {
        // cancel any in-flight trade registration/fetch of this wizard
        // (in-flight payments are not cancelled, they save the trade on success)
        AppController.plugin('escrow').cancelPendingFlow()
    }
}
