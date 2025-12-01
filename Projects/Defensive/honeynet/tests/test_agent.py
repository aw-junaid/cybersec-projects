#!/usr/bin/env python3
"""
Tests for Honeynet Agent
"""

import os
import pytest
import asyncio
from unittest.mock import Mock, patch
from collector.agent.app import HoneynetAgent, EnrichedEvent

@pytest.fixture
def agent():
    """Create agent instance for testing"""
    with patch.dict(os.environ, {
        'HONEY_LAB_MODE': '1',
        'NODE_TOKEN': 'test-token-123',
        'KAFKA_BROKERS': 'localhost:9092'
    }):
        return HoneynetAgent()

@pytest.mark.asyncio
async def test_agent_initialization(agent):
    """Test agent initialization"""
    with patch.object(agent, '_verify_safety'), \
         patch.object(agent, '_verify_config'), \
         patch('kafka.KafkaProducer'):
        await agent.initialize()
        assert agent.kafka_producer is not None

@pytest.mark.asyncio
async def test_event_enrichment(agent):
    """Test event enrichment"""
    raw_event = {
        'event_type': 'ssh_login',
        'src_ip': '192.168.1.100',
        'src_port': 54321,
        'dest_ip': '192.168.1.10',
        'dest_port': 22,
        'protocol': 'tcp'
    }
    
    with patch.object(agent, 'geoip_reader', None):
        enriched = await agent.enrich_event(raw_event)
        
        assert enriched.event_type == 'ssh_login'
        assert enriched.source_ip == '192.168.1.100'
        assert enriched.sensor_id == 'test-tok'

def test_safety_check_fails_without_env():
    """Test safety check requires HONEY_LAB_MODE"""
    if 'HONEY_LAB_MODE' in os.environ:
        del os.environ['HONEY_LAB_MODE']
    
    with pytest.raises(Exception):
        HoneynetAgent()

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
