from typing import TYPE_CHECKING, Dict, Any
from electrum.wizard import AbstractWizard, WizardViewState

if TYPE_CHECKING:
    from .escrow import EscrowPlugin

class EscrowWizard(AbstractWizard):
    def __init__(self, plugin: 'EscrowPlugin'):
        super().__init__()
        self.plugin = plugin
        self.navmap = {
            'create_trade': {
                'next': 'select_escrow_agent',
            },
            'select_escrow_agent': {
                'next': 'confirm_create',
            },
            'confirm_create': {
                'last': True,
            },
            'fetch_trade': {
                'next': 'accept_trade',
            },
            'accept_trade': {
                'last': True,
            }
        }

    def start(self, start_viewstate: WizardViewState) -> WizardViewState:
        assert start_viewstate
        self.reset()
        self._current = start_viewstate
        return self._current
