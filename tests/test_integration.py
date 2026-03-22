from __future__ import annotations

import pytest
import os
import asyncio
from uuid import uuid4
from datetime import datetime
from main import app
from httpx import AsyncClient, ASGITransport
import pytest

@pytest.mark.asyncio
async def test_full_pipeline_integration():
    """
    Integration test for the full analysis pipeline.
    This test uploads a sample file, triggers analysis, and verifies the output structure.
    Note: Requires Ollama to be running for agent analysis to succeed, 
    otherwise it will test up to the agent failure point.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health check
        response = await client.get("/health")
        assert response.status_code == 200
        health = response.json()
        assert health["status"] == "healthy"
        
        # 2. Upload sample file
        test_file_path = "tests/fixtures/sample_firewall.csv"
        if not os.path.exists(test_file_path):
            pytest.skip("Sample firewall file not found")
            
        with open(test_file_path, "rb") as f:
            response = await client.post(
                "/api/v1/files/upload",
                files={"file": ("sample_firewall.csv", f, "text/csv")}
            )
        
        assert response.status_code == 201
        file_info = response.json()
        file_id = file_info["file_id"]
        assert file_id is not None
        
        # 3. Trigger full analysis
        # We'll use a timeout since AI analysis can be slow
        try:
            response = await client.post(f"/api/v1/analyze?file_id={file_id}", timeout=60.0)
            assert response.status_code == 200
            result = response.json()
            
            # 4. Verify pipeline results
            assert result["file_id"] == file_id
            assert result["events_parsed"] > 0
            assert result["chunks_created"] > 0
            
            # If Ollama is running and configured, we should see analyses/incidents
            # If not, the pipeline should still finish but with 0 analyses or errors
            print(f"Pipeline result: {result}")
            
        except Exception as e:
            # If Ollama is not running, we might get a connection error in the agents module
            # For CI purposes, we want to ensure the pipeline logic itself is sound
            if "Connection" in str(e) or "Timeout" in str(e):
                print(f"Agent analysis skipped or failed due to environment: {e}")
            else:
                raise e

@pytest.mark.asyncio
async def test_incident_management_flow():
    """Test the incident management API flow."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. List incidents (initially empty or from previous runs)
        response = await client.get("/api/v1/incidents/")
        assert response.status_code == 200
        incidents = response.json()
        
        # 2. Get stats
        response = await client.get("/api/v1/incidents/stats")
        assert response.status_code == 200
        stats = response.json()
        assert "total_incidents" in stats
