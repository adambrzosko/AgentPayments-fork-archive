from django.conf import settings
from django.core.management.base import BaseCommand

from gate.services.solana import derive_payment_memo, verify_payment_via_backend


class Command(BaseCommand):
    help = "Verify a USDC payment via the backend for a given agent key"

    def add_arguments(self, parser):
        parser.add_argument("agent_key", help="The agent key to verify payment for")

    def handle(self, *args, **options):
        agent_key = options["agent_key"]
        verify_url = settings.AGENTPAYMENTS_VERIFY_URL
        api_key = settings.AGENTPAYMENTS_API_KEY

        if not verify_url or not api_key:
            self.stderr.write(
                self.style.ERROR("Error: AGENTPAYMENTS_VERIFY_URL and AGENTPAYMENTS_API_KEY must be set.")
            )
            return

        memo = derive_payment_memo(agent_key, settings.CHALLENGE_SECRET)
        self.stdout.write(f"Agent key: {agent_key}")
        self.stdout.write(f"Memo:      {memo}")
        self.stdout.write(f"Verify URL: {verify_url}")
        self.stdout.write("")

        result = verify_payment_via_backend(memo, verify_url, api_key)

        if result:
            self.stdout.write(self.style.SUCCESS("VERIFIED - payment found."))
        else:
            self.stdout.write(self.style.ERROR("NOT VERIFIED - no matching payment found."))
