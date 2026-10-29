"""add_cspm_platform_models

Revision ID: a3c7e9f12b45
Revises: 17333f4fa8bd
Create Date: 2026-10-25 23:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3c7e9f12b45'
down_revision: Union[str, Sequence[str]] = '17333f4fa8bd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Cloud Environments
    op.create_table(
        'cloud_environments',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(100), nullable=False, index=True),
        sa.Column('provider', sa.String(20), nullable=False, index=True),
        sa.Column('account_id', sa.String(200), nullable=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('region', sa.String(100), nullable=True),
        sa.Column('connection_status', sa.String(30), server_default='NOT_CONNECTED'),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('health_status', sa.String(30), server_default='UNKNOWN'),
        sa.Column('connector_version', sa.String(50), nullable=True),
        sa.Column('config_json', sa.Text(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('idx_cloud_env_tenant_provider', 'cloud_environments', ['tenant_id', 'provider'])

    # CSPM Agents
    op.create_table(
        'cspm_agents',
        sa.Column('id', sa.String(100), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('tenant_id', sa.String(100), nullable=False, index=True),
        sa.Column('environment_id', sa.String(64), sa.ForeignKey('cloud_environments.id'), nullable=True, index=True),
        sa.Column('cloud_provider', sa.String(20), nullable=True),
        sa.Column('cloud_account_id', sa.String(200), nullable=True),
        sa.Column('deployment_environment', sa.String(50), server_default='development'),
        sa.Column('region', sa.String(100), nullable=True),
        sa.Column('framework', sa.String(100), nullable=True),
        sa.Column('model_provider', sa.String(100), nullable=True),
        sa.Column('model_name', sa.String(100), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tools_json', sa.Text(), server_default='[]'),
        sa.Column('mcp_servers_json', sa.Text(), server_default='[]'),
        sa.Column('registration_source', sa.String(50), server_default='manual'),
        sa.Column('status', sa.String(30), server_default='ACTIVE', index=True),
        sa.Column('connection_status', sa.String(30), server_default='UNKNOWN'),
        sa.Column('risk_score', sa.Float(), server_default='0.0'),
        sa.Column('open_findings_count', sa.Integer(), server_default='0'),
        sa.Column('critical_findings_count', sa.Integer(), server_default='0'),
        sa.Column('high_findings_count', sa.Integer(), server_default='0'),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )

    # Security Findings
    op.create_table(
        'security_findings',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('rule_id', sa.String(100), nullable=True, index=True),
        sa.Column('tenant_id', sa.String(100), nullable=False, index=True),
        sa.Column('agent_id', sa.String(100), sa.ForeignKey('cspm_agents.id'), nullable=True, index=True),
        sa.Column('environment_id', sa.String(64), sa.ForeignKey('cloud_environments.id'), nullable=True, index=True),
        sa.Column('resource_id', sa.String(300), nullable=True),
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(100), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('confidence', sa.String(20), server_default='HIGH'),
        sa.Column('cloud_provider', sa.String(20), nullable=True),
        sa.Column('detection_source', sa.String(100), nullable=True),
        sa.Column('evidence_json', sa.Text(), server_default='{}'),
        sa.Column('technical_detail', sa.Text(), nullable=True),
        sa.Column('impact', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('compliance_frameworks_json', sa.Text(), server_default='[]'),
        sa.Column('status', sa.String(30), server_default='OPEN', index=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('idx_finding_tenant_severity', 'security_findings', ['tenant_id', 'severity'])
    op.create_index('idx_finding_tenant_status', 'security_findings', ['tenant_id', 'status'])

    # Finding History
    op.create_table(
        'finding_history',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('finding_id', sa.String(64), sa.ForeignKey('security_findings.id'), nullable=False, index=True),
        sa.Column('previous_status', sa.String(30), nullable=True),
        sa.Column('new_status', sa.String(30), nullable=False),
        sa.Column('changed_by', sa.String(100), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
    )

    # CSPM Scan Jobs
    op.create_table(
        'cspm_scan_jobs',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', sa.String(100), nullable=False, index=True),
        sa.Column('target_agent_id', sa.String(100), sa.ForeignKey('cspm_agents.id'), nullable=True),
        sa.Column('target_environment_id', sa.String(64), sa.ForeignKey('cloud_environments.id'), nullable=True),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(30), server_default='PENDING', index=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_checks', sa.Integer(), server_default='0'),
        sa.Column('passed_checks', sa.Integer(), server_default='0'),
        sa.Column('failed_checks', sa.Integer(), server_default='0'),
        sa.Column('warning_checks', sa.Integer(), server_default='0'),
        sa.Column('findings_count', sa.Integer(), server_default='0'),
        sa.Column('severity_distribution_json', sa.Text(), server_default='{}'),
        sa.Column('coverage_json', sa.Text(), server_default='{}'),
        sa.Column('error_detail', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    )

    # CSPM Rules
    op.create_table(
        'cspm_rules',
        sa.Column('id', sa.String(100), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('category', sa.String(100), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('detection_logic_status', sa.String(30), server_default='NOT_IMPLEMENTED'),
        sa.Column('framework_mapping_json', sa.Text(), server_default='[]'),
        sa.Column('version', sa.String(20), server_default='1.0.0'),
        sa.Column('is_active', sa.Boolean(), server_default='1'),
        sa.Column('last_validated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_validation_status', sa.String(30), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('cspm_rules')
    op.drop_table('cspm_scan_jobs')
    op.drop_table('finding_history')
    op.drop_table('security_findings')
    op.drop_table('cspm_agents')
    op.drop_table('cloud_environments')
