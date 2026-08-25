from django.conf import settings
from django.core.management.base import BaseCommand

from gate.services.solana import (
    RPC_DEVNET,
    RPC_MAINNET,
    USDC_MINT_DEVNET,
    USDC_MINT_MAINNET,
    verify_payment_on_chain,
)


class Command(BaseCommand):
    help = "Verify a USDC payment on-chain for a given agent key"

    def add_arguments(self, parser):
        parser.add_argument("agent_key", help="The agent key to verify payment for")

    def handle(self, *args, **options):
        agent_key = options["agent_key"]
        wallet_address = settings.HOME_WALLET_ADDRESS
        debug = settings.DEBUG

        if not wallet_address:
            self.stderr.write(self.style.ERROR("Error: HOME_WALLET_ADDRESS must be set."))
            return

        rpc_url = settings.SOLANA_RPC_URL or (RPC_DEVNET if debug else RPC_MAINNET)
        usdc_mint = settings.USDC_MINT or (USDC_MINT_DEVNET if debug else USDC_MINT_MAINNET)

        self.stdout.write(f"Agent key: {agent_key}")
        self.stdout.write(f"Wallet:    {wallet_address}")
        self.stdout.write(f"RPC:       {rpc_url}")
        self.stdout.write("")

        result = verify_payment_on_chain(agent_key, wallet_address, rpc_url, usdc_mint)

        if result:
            self.stdout.write(self.style.SUCCESS("VERIFIED - payment found."))
        else:
            self.stdout.write(self.style.ERROR("NOT VERIFIED - no matching payment found."))
