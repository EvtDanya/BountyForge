import logging
from datetime import datetime
from flask import Request
from dataclasses import asdict
from ..schemas import HoneypotEvent, HoneypotEventMetadata, AttackType
from ..publishers import AMQPPublisher, MQTTPublisher

logger = logging.getLogger(__name__)


class EventSender:
    def __init__(self, publishers: list[AMQPPublisher | MQTTPublisher]):
        self.publishers = publishers

    def send_event(
        self,
        req: Request,
        action: str,
        attack_type: AttackType,
        filepath: str = None
    ):
        metadata = HoneypotEventMetadata(
            action=action,
            attack_type=attack_type,
            request=req,
            filepath=filepath
        )
        event = HoneypotEvent(
            source_ip=req.remote_addr,
            source_port=req.environ.get('REMOTE_PORT'),
            destination_ip=req.server[0],
            destination_port=req.server[1] or 80,
            protocol=req.scheme,
            timestamp=datetime.now(),
            metadata=metadata
        )
        logger.debug(event)

        for publisher in self.publishers:
            publisher.publish_msg(asdict(event))
