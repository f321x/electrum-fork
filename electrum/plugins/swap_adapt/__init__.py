from typing import TYPE_CHECKING

from electrum.commands import plugin_command

if TYPE_CHECKING:
    from electrum.commands import Commands
    from .swap_adapt import SwapAdaptPlugin

PLUGIN_NAME = "swap_adapt"

@plugin_command('', PLUGIN_NAME)
async def enable_telegram_notifications(
    self: 'Commands',
    bot_token: str = None,
    chat_id: str = None,
    plugin: 'SwapAdaptPlugin' = None
) -> str:
    """
    Enable telegram notification bot and store connection data in plugin storage.
    You have to message your bot first for it to be able to message you. Otherwise it will fail.

    arg:str:bot_token: Telegram bot token
    arg:str:chat_id: Telegram chat ID
    """
    assert plugin.storage is not None, "Plugin storage is not initialized, load_wallet first"
    assert bot_token, "bot_token is required"
    assert chat_id, "chat_id is required"
    plugin.storage['telegram'] = {
        'bot_token': bot_token,
        'chat_id': chat_id,
    }
    try:
        await plugin.send_telegram_notification(
            "Telegram notifications enabled. Use disable_telegram_notifications to disable again."
        )
    except Exception:
        del plugin.storage['telegram']
        raise
    return "Telegram notifications enabled. Use disable_telegram_notifications to disable again."

@plugin_command('', PLUGIN_NAME)
async def disable_telegram_notifications(
    self: 'Commands',
    plugin: 'SwapAdaptPlugin' = None
) -> str:
    """
    Disable telegram notification bot and delete connection data.
    """
    assert plugin.storage is not None, "Plugin storage is not initialized, load_wallet first"
    try:
        del plugin.storage['telegram']
    except KeyError:
        return "Telegram notifications were not enabled"
    return f"disabled and removed connection"
