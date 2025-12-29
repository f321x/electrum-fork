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
                'next': 'create_confirm',
            },
            'confirm_create': {
                'last': True
            },
            'fetch_trade': {
                'next': 'accept_trade',
            },
            'accept_trade': {
                'last': True,
            }
        }

    def start(self, flow_type: str) -> WizardViewState:
        self.reset()
        start_view = 'create_trade' if flow_type == 'create' else 'fetch_trade'
        self._current = WizardViewState(start_view, {}, {})
        return self._current
