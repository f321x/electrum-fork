import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    objectName: 'Console'

    property string title: qsTr('Console')

    padding: 0

    property var _completions: undefined

    function runCommand() {
        root._completions = undefined
        PyConsole.runCommand(cmdField.text)
        cmdField.text = ''
        cmdField.forceActiveFocus()
    }

    function complete() {
        var result = PyConsole.getCompletions(cmdField.text)
        cmdField.text = result.text
        cmdField.cursorPosition = cmdField.text.length
        root._completions = result.candidates.length > 0 ? result : undefined
        cmdField.forceActiveFocus()
    }

    function setCommand(text) {
        cmdField.text = text
        cmdField.cursorPosition = text.length
        cmdField.forceActiveFocus()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        InfoTextArea {
            id: warningBanner
            Layout.fillWidth: true
            Layout.margins: constants.paddingMedium
            iconStyle: InfoTextArea.IconStyle.Warn
            text: qsTr("Do not paste code here that you don't understand. Executing the wrong code could lead to your coins being irreversibly lost.")
                + ' ' + qsTr('Tap here to hide this message.')

            MouseArea {
                anchors.fill: parent
                onClicked: warningBanner.visible = false
            }
        }

        Flickable {
            id: outputFlickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingXSmall
            Layout.rightMargin: constants.paddingXSmall
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            function scrollToEnd() {
                if (contentHeight > height)
                    contentY = contentHeight - height
                else
                    contentY = 0
            }

            TextArea.flickable: TextArea {
                id: outputText
                text: PyConsole.output
                readOnly: true
                font.family: FixedFont
                font.pixelSize: constants.fontSizeSmall
                wrapMode: TextEdit.WrapAnywhere
                textFormat: TextEdit.PlainText
            }

            ScrollBar.vertical: ScrollBar { }

            Connections {
                target: PyConsole
                function onOutputChanged() {
                    Qt.callLater(outputFlickable.scrollToEnd)
                }
            }
        }

        Flickable {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            visible: root._completions !== undefined
            implicitHeight: completionsRow.height
            contentWidth: completionsRow.width
            clip: true
            flickableDirection: Flickable.HorizontalFlick

            Row {
                id: completionsRow
                spacing: constants.paddingXSmall

                Repeater {
                    model: root._completions !== undefined ? root._completions.candidates : []

                    Button {
                        text: modelData.split('.').pop()
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                        onClicked: {
                            root.setCommand(root._completions.beginning + modelData)
                            root._completions = undefined
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingMedium
            Layout.rightMargin: constants.paddingMedium
            spacing: constants.paddingXSmall

            Label {
                text: PyConsole.prompt
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                color: Material.accentColor
            }

            TextField {
                id: cmdField
                Layout.fillWidth: true
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhSensitiveData | Qt.ImhNoAutoUppercase
                onAccepted: root.runCommand()
            }

            ToolButton {
                icon.source: '../../icons/closebutton.png'
                icon.color: constants.colorError
                visible: PyConsole.inConstruct
                onClicked: {
                    PyConsole.keyboardInterrupt()
                    cmdField.forceActiveFocus()
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: '▲'
                onClicked: root.setCommand(PyConsole.getPrevHistoryEntry())
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: '▼'
                onClicked: root.setCommand(PyConsole.getNextHistoryEntry())
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Tab')
                onClicked: root.complete()
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Run')
                onClicked: root.runCommand()
            }
        }
    }

    property color navigationBarBackgroundColor: constants.highlightBackground
}
