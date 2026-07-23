# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the SkillSpector FastAPI service skeleton."""

from __future__ import annotations

from fastapi.testclient import TestClient

from skillspector import __version__
from skillspector.api.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    """Health endpoint returns runtime metadata and service identity."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "skillspector-api"
    assert data["scanner_version"] == __version__
    assert "data_dir" in data
    assert "work_dir" in data


def test_version_endpoint() -> None:
    """Version endpoint returns the installed scanner version."""
    response = client.get("/v1/version")

    assert response.status_code == 200
    assert response.json() == {
        "service": "skillspector-api",
        "scanner_version": __version__,
    }
