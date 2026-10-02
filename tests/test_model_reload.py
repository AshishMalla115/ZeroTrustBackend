import pytest
from fastapi import status
import os

@pytest.fixture()
def reload_ready(stub_engine):
    class _FakeLib:
        @staticmethod
        def re_engine_reload_model(engine, path):
            return 0          # 0 = success, as the real function returns
    stub_engine._lib = _FakeLib()
    stub_engine._engine = None
    return stub_engine


@pytest.mark.postgres
def test_model_reload_twice_active_one(client, admin_token, db_session, reload_ready):
    model_file = "model.isof"
    # First reload
    resp1 = client.post(f"/admin/model/reload?model_path={model_file}",
                        headers={"Authorization": f"Bearer {admin_token}"})
    assert resp1.status_code == status.HTTP_200_OK
    data1 = resp1.json()
    assert data1["model_path"] == model_file
    assert "model_version_id" in data1

    # Second reload same file
    resp2 = client.post(f"/admin/model/reload?model_path={model_file}",
                        headers={"Authorization": f"Bearer {admin_token}"})
    assert resp2.status_code == status.HTTP_200_OK
    data2 = resp2.json()
    assert data2["model_version_id"] != data1["model_version_id"]

    # Verify only one active row
    from app.models.db_models import MLModelVersion
    active = db_session.query(MLModelVersion).filter(MLModelVersion.active == True).all()
    assert len(active) == 1
    assert str(active[0].id) == data2["model_version_id"]