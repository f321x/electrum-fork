import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum

import "../../../gui/qml/components/controls"

ElDialog {
    id: dialog

    property var plugin: AppController.plugin('escrow')
    property string avatarSource: ''

    title: qsTr('Escrow Agent Profile')
    iconSource: Qt.resolvedUrl('../escrow-icon.png')

    width: parent.width
    height: parent.height
    padding: 0

    // mirror the limits enforced when customers parse the profile
    function languagesValid() {
        var langs = languagesEdit.text.split(',').map(function(s) { return s.trim() })
            .filter(function(s) { return s != '' })
        if (langs.length > 20)
            return false
        for (var i = 0; i < langs.length; i++) {
            if (langs[i].length > 20)
                return false
        }
        return true
    }

    property bool formValid: nameEdit.text.trim() != ''
        && aboutEdit.text.trim() != ''
        && (pictureEdit.text.trim() == '' || pictureEdit.text.trim().startsWith('https://'))
        && (websiteEdit.text.trim() == '' || websiteEdit.text.trim().startsWith('https://'))
        && languagesValid()

    Component.onCompleted: {
        var profile = plugin.getProfile()
        if (profile.found) {
            nameEdit.text = profile.name
            aboutEdit.text = profile.about
            languagesEdit.text = profile.languagesText
            feeSpinBox.value = profile.feePpm
            gpgEdit.text = profile.gpg
            pictureEdit.text = profile.picture
            websiteEdit.text = profile.website
            if (profile.picture != '')
                plugin.fetchAvatar(profile.picture)
        }
    }

    Connections {
        target: plugin
        function onAvatarReceived(url, dataUrl) {
            if (pictureEdit.text.trim() == url)
                avatarSource = dataUrl
        }
    }

    Timer {
        id: avatarFetchTimer
        interval: 800
        repeat: false
        onTriggered: {
            var url = pictureEdit.text.trim()
            if (url.startsWith('https://'))
                plugin.fetchAvatar(url)
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

            GridLayout {
                id: contentLayout
                width: parent.width - 2 * constants.paddingLarge
                x: constants.paddingLarge
                columns: 2

                Image {
                    Layout.columnSpan: 2
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: constants.paddingLarge
                    Layout.preferredWidth: constants.iconSizeXXLarge
                    Layout.preferredHeight: constants.iconSizeXXLarge
                    visible: avatarSource != ''
                    source: avatarSource
                    fillMode: Image.PreserveAspectFit
                }

                RowLayout {
                    Label {
                        text: qsTr('Name')
                        color: Material.accentColor
                    }
                    HelpButton {
                        heading: qsTr('Name')
                        helptext: qsTr('The name that will be displayed to other users.')
                    }
                }

                TextField {
                    id: nameEdit
                    Layout.fillWidth: true
                    maximumLength: 50
                    placeholderText: qsTr('Enter your display name')
                }

                RowLayout {
                    Layout.columnSpan: 2
                    Label {
                        text: qsTr('About')
                        color: Material.accentColor
                    }
                    HelpButton {
                        heading: qsTr('About')
                        helptext: qsTr('A description of your services, your terms, how to contact you in case of mediation, and any other relevant information.')
                    }
                }

                ElTextArea {
                    id: aboutEdit
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.minimumHeight: 120
                    wrapMode: TextEdit.Wrap
                    placeholderText: qsTr('Enter a description (max 1000 characters)...')
                    onTextChanged: {
                        if (text.length > 1000) {
                            text = text.substring(0, 1000)
                            cursorPosition = text.length
                        }
                    }
                }

                RowLayout {
                    Label {
                        text: qsTr('Languages')
                        color: Material.accentColor
                    }
                    HelpButton {
                        heading: qsTr('Languages')
                        helptext: qsTr('Comma-separated list of languages you support for dispute resolution.')
                    }
                }

                TextField {
                    id: languagesEdit
                    Layout.fillWidth: true
                    maximumLength: 100
                    placeholderText: qsTr('e.g. en, es, de')
                }

                RowLayout {
                    Label {
                        text: qsTr('Service Fee')
                        color: Material.accentColor
                    }
                    HelpButton {
                        heading: qsTr('Service Fee')
                        helptext: qsTr('Your fee in parts per million of the trade amount. 10,000 ppm is 1%. Note: the fee is locked into each trade at creation, changing it only affects new trades.')
                    }
                }

                RowLayout {
                    SpinBox {
                        id: feeSpinBox
                        from: 0
                        to: plugin.maxAgentFeePpm
                        editable: true
                    }
                    Label {
                        text: qsTr('ppm')
                        color: Material.accentColor
                    }
                }

                RowLayout {
                    Label {
                        text: qsTr('GPG')
                        color: Material.accentColor
                    }
                    HelpButton {
                        heading: qsTr('GPG Fingerprint')
                        helptext: qsTr('Your GPG key fingerprint for identity verification.')
                    }
                }

                TextField {
                    id: gpgEdit
                    Layout.fillWidth: true
                    maximumLength: 100
                    placeholderText: qsTr('[Optional] Enter your GPG fingerprint')
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                }

                Label {
                    text: qsTr('Picture')
                    color: Material.accentColor
                }

                TextField {
                    id: pictureEdit
                    Layout.fillWidth: true
                    maximumLength: 200
                    placeholderText: '[Optional] https://example.com/avatar.png'
                    font.pixelSize: constants.fontSizeSmall
                    onTextChanged: avatarFetchTimer.restart()
                }

                Label {
                    text: qsTr('Website')
                    color: Material.accentColor
                }

                TextField {
                    id: websiteEdit
                    Layout.fillWidth: true
                    maximumLength: 200
                    placeholderText: '[Optional] https://example.com/'
                    font.pixelSize: constants.fontSizeSmall
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Save')
                icon.source: Qt.resolvedUrl('../../../gui/icons/confirmed.png')
                enabled: dialog.formValid
                onClicked: {
                    var error = plugin.saveProfile({
                        'name': nameEdit.text,
                        'about': aboutEdit.text,
                        'languagesText': languagesEdit.text,
                        'feePpm': feeSpinBox.value,
                        'gpg': gpgEdit.text,
                        'picture': pictureEdit.text,
                        'website': websiteEdit.text
                    })
                    if (error != '') {
                        var msgdialog = app.messageDialog.createObject(app, {
                            title: qsTr('Error'),
                            iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
                            text: error
                        })
                        msgdialog.open()
                        return
                    }
                    dialog.doAccept()
                }
            }
        }
    }
}
