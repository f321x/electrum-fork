import math
import re

from time import time
from typing import Tuple, TYPE_CHECKING

from electrum.i18n import _

if TYPE_CHECKING:
    from electrum.transaction import Transaction

# max inputs+outputs and max serialized size for which we attempt to generate
# a QR code of a tx. The base43 encoding done by to_qr_data() gets prohibitively
# slow for large txs (quadratic in size), and such txs cannot fit in a QR code
# anyway (max ~3 kB at the highest QR version).
_TX_QR_MAX_TXIOS = 20
_TX_QR_MAX_SIZE_BYTES = 3000


def tx_qr_data_or_empty(tx: 'Transaction') -> Tuple[str, bool]:
    """Return tx.to_qr_data(), or ('', False) if the tx is too large for a QR code."""
    if len(tx.inputs()) + len(tx.outputs()) > _TX_QR_MAX_TXIOS:
        return '', False
    if tx.estimated_total_size() > _TX_QR_MAX_SIZE_BYTES:
        return '', False
    return tx.to_qr_data()


# return delay in msec when expiry time string should be updated
# returns 0 when expired or expires > 1 day away (no updates needed)
def status_update_timer_interval(exp):
    # very roughly according to util.age
    exp_in = int(exp - time())
    exp_in_min = int(exp_in/60)

    interval = 0
    if exp_in < 0:
        interval = 0
    elif exp_in_min < 2:
        interval = 1000
    elif exp_in_min < 90:
        interval = 1000 * 60
    elif exp_in_min < 1440:
        interval = 1000 * 60 * 60

    return interval


# TODO: copied from qt password_dialog.py, move to common code
def check_password_strength(password: str) -> Tuple[int, str]:
    """Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong"""
    password = password
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*(n + caps + num + extra)/20
    password_strength = {0: _('Weak'), 1: _('Medium'), 2: _('Strong'), 3: _('Very Strong')}
    return min(3, int(score)), password_strength[min(3, int(score))]
