from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from storage.database import a_session_maker
from storage.stored_offline_token import StoredOfflineToken

from openhands.app_server.utils.logger import openhands_logger as logger


# Offline tokens are long-lived refresh credentials: a leaked one is replayable
# for as long as the record survives. Bound their lifetime in the application so
# a stolen token stops working even when the IdP session would still honour it.
OFFLINE_TOKEN_TTL = timedelta(days=30)


@dataclass
class OfflineTokenStore:
    user_id: str

    async def store_token(self, offline_token: str) -> None:
        """Store an offline token in the database."""
        async with a_session_maker() as session:
            result = await session.execute(
                select(StoredOfflineToken).where(
                    StoredOfflineToken.user_id == self.user_id
                )
            )
            token_record = result.scalar_one_or_none()

            expires_at = datetime.utcnow() + OFFLINE_TOKEN_TTL
            if token_record:
                token_record.offline_token = offline_token
                # Re-storing is a fresh issuance, so the clock restarts.
                token_record.expires_at = expires_at
            else:
                token_record = StoredOfflineToken(
                    user_id=self.user_id,
                    offline_token=offline_token,
                    expires_at=expires_at,
                )
                session.add(token_record)
            await session.commit()

    async def load_token(self) -> str | None:
        """Load an offline token from the database."""
        async with a_session_maker() as session:
            result = await session.execute(
                select(StoredOfflineToken).where(
                    StoredOfflineToken.user_id == self.user_id
                )
            )
            token_record = result.scalar_one_or_none()

            if not token_record:
                return None

            # Fail closed on both the expired and the legacy (NULL) case. A row
            # written before this column existed has no provable issuance time,
            # so treating NULL as "never expires" would exempt exactly the
            # oldest tokens -- the ones most likely to have leaked.
            if (
                token_record.expires_at is None
                or datetime.utcnow() > token_record.expires_at
            ):
                logger.info(
                    'offline_token_expired',
                    extra={
                        'user_id': self.user_id,
                        'expires_at': str(token_record.expires_at),
                    },
                )
                return None

            return token_record.offline_token

    @classmethod
    async def get_instance(
        cls,
        user_id: str,
    ) -> OfflineTokenStore:
        """Get an instance of the OfflineTokenStore.

        TODO: This method should be replaced with dependency injection.
        """
        logger.debug(f'offline_token_store.get_instance::{user_id}')
        return OfflineTokenStore(user_id)
