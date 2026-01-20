"use client";

import React from "react";
import { MobSFPendingDecision } from "@/context/ScanContext";

interface MobSFDecisionDialogProps {
    pending: MobSFPendingDecision;
    onDecision: (decision: "STOP" | "CONTINUE") => void;
    isSubmitting?: boolean;
}

export function MobSFDecisionDialog({ pending, onDecision, isSubmitting = false }: MobSFDecisionDialogProps) {
    return (
        <div className="mobsf-decision-overlay">
            <div className="mobsf-decision-dialog">
                {/* Header */}
                <div className="dialog-header">
                    <div className="header-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M12 9v4m0 4h.01M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Z" />
                        </svg>
                    </div>
                    <h2>MobSF Analysis Complete</h2>
                    <p className="subtitle">Review the static analysis results and decide how to proceed</p>
                </div>

                {/* App Info */}
                <div className="app-info">
                    <div className="app-icon">📱</div>
                    <div className="app-details">
                        <h3>{pending.appName}</h3>
                        <p className="package-name">{pending.packageName}</p>
                        <p className="file-name">{pending.fileName}</p>
                    </div>
                </div>

                {/* Security Score */}
                <div className="security-score-section">
                    <div className="score-circle" data-score={getScoreLevel(pending.securityScore)}>
                        <span className="score-value">{pending.securityScore}</span>
                        <span className="score-label">Security Score</span>
                    </div>
                    <div className="score-description">
                        {getScoreDescription(pending.securityScore)}
                    </div>
                </div>

                {/* Severity Breakdown */}
                <div className="severity-breakdown">
                    <h4>Findings Summary</h4>
                    <div className="severity-grid">
                        <div className="severity-item high">
                            <span className="count">{pending.severityCounts.high}</span>
                            <span className="label">High</span>
                        </div>
                        <div className="severity-item warning">
                            <span className="count">{pending.severityCounts.warning}</span>
                            <span className="label">Warning</span>
                        </div>
                        <div className="severity-item info">
                            <span className="count">{pending.severityCounts.info}</span>
                            <span className="label">Info</span>
                        </div>
                    </div>
                </div>

                {/* Frida Section */}
                <div className="frida-section">
                    <div className="frida-icon">🔬</div>
                    <div className="frida-info">
                        <h4>Continue with Dynamic Analysis?</h4>
                        <p>
                            Frida will perform runtime analysis on the app to detect additional
                            vulnerabilities that static analysis cannot find, such as insecure
                            data storage, runtime tampering, and API security issues.
                        </p>
                    </div>
                </div>

                {/* Action Buttons */}
                <div className="dialog-actions">
                    <button
                        className="btn-stop"
                        onClick={() => onDecision("STOP")}
                        disabled={isSubmitting}
                    >
                        {isSubmitting ? "Processing..." : "Stop Here"}
                        <span className="btn-hint">Save current results</span>
                    </button>
                    <button
                        className="btn-continue"
                        onClick={() => onDecision("CONTINUE")}
                        disabled={isSubmitting}
                    >
                        {isSubmitting ? "Processing..." : "Continue with Frida"}
                        <span className="btn-hint">Run dynamic analysis</span>
                    </button>
                </div>
            </div>

            <style jsx>{`
                .mobsf-decision-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0, 0, 0, 0.7);
                    backdrop-filter: blur(4px);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 1000;
                    padding: 20px;
                }

                .mobsf-decision-dialog {
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 16px;
                    padding: 32px;
                    max-width: 520px;
                    width: 100%;
                    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                }

                .dialog-header {
                    text-align: center;
                    margin-bottom: 24px;
                }

                .header-icon {
                    width: 48px;
                    height: 48px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 12px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 16px;
                    color: white;
                }

                .dialog-header h2 {
                    margin: 0;
                    font-size: 1.5rem;
                    font-weight: 600;
                    color: #fff;
                }

                .dialog-header .subtitle {
                    margin: 8px 0 0;
                    color: rgba(255, 255, 255, 0.6);
                    font-size: 0.9rem;
                }

                .app-info {
                    display: flex;
                    align-items: center;
                    gap: 16px;
                    background: rgba(255, 255, 255, 0.05);
                    padding: 16px;
                    border-radius: 12px;
                    margin-bottom: 24px;
                }

                .app-icon {
                    font-size: 2.5rem;
                }

                .app-details h3 {
                    margin: 0;
                    font-size: 1.1rem;
                    color: #fff;
                }

                .app-details .package-name {
                    margin: 4px 0 0;
                    font-size: 0.85rem;
                    color: rgba(255, 255, 255, 0.6);
                    font-family: monospace;
                }

                .app-details .file-name {
                    margin: 2px 0 0;
                    font-size: 0.8rem;
                    color: rgba(255, 255, 255, 0.4);
                }

                .security-score-section {
                    display: flex;
                    align-items: center;
                    gap: 20px;
                    margin-bottom: 24px;
                }

                .score-circle {
                    width: 80px;
                    height: 80px;
                    border-radius: 50%;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    flex-shrink: 0;
                }

                .score-circle[data-score="critical"] {
                    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
                }
                .score-circle[data-score="low"] {
                    background: linear-gradient(135deg, #f97316 0%, #c2410c 100%);
                }
                .score-circle[data-score="medium"] {
                    background: linear-gradient(135deg, #eab308 0%, #a16207 100%);
                }
                .score-circle[data-score="high"] {
                    background: linear-gradient(135deg, #22c55e 0%, #15803d 100%);
                }

                .score-value {
                    font-size: 1.5rem;
                    font-weight: 700;
                    color: white;
                }

                .score-label {
                    font-size: 0.7rem;
                    color: rgba(255, 255, 255, 0.8);
                }

                .score-description {
                    color: rgba(255, 255, 255, 0.7);
                    font-size: 0.9rem;
                    line-height: 1.5;
                }

                .severity-breakdown {
                    margin-bottom: 24px;
                }

                .severity-breakdown h4 {
                    margin: 0 0 12px;
                    font-size: 0.9rem;
                    color: rgba(255, 255, 255, 0.8);
                    font-weight: 500;
                }

                .severity-grid {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 12px;
                }

                .severity-item {
                    background: rgba(255, 255, 255, 0.05);
                    padding: 12px;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }

                .severity-item.high {
                    border-color: rgba(239, 68, 68, 0.5);
                    background: rgba(239, 68, 68, 0.1);
                }

                .severity-item.warning {
                    border-color: rgba(245, 158, 11, 0.5);
                    background: rgba(245, 158, 11, 0.1);
                }

                .severity-item.info {
                    border-color: rgba(59, 130, 246, 0.5);
                    background: rgba(59, 130, 246, 0.1);
                }

                .severity-item .count {
                    display: block;
                    font-size: 1.5rem;
                    font-weight: 700;
                    color: #fff;
                }

                .severity-item .label {
                    font-size: 0.75rem;
                    color: rgba(255, 255, 255, 0.6);
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }

                .frida-section {
                    display: flex;
                    gap: 16px;
                    background: rgba(99, 102, 241, 0.1);
                    border: 1px solid rgba(99, 102, 241, 0.3);
                    padding: 16px;
                    border-radius: 12px;
                    margin-bottom: 24px;
                }

                .frida-icon {
                    font-size: 2rem;
                }

                .frida-info h4 {
                    margin: 0 0 8px;
                    font-size: 1rem;
                    color: #fff;
                }

                .frida-info p {
                    margin: 0;
                    font-size: 0.85rem;
                    color: rgba(255, 255, 255, 0.6);
                    line-height: 1.5;
                }

                .dialog-actions {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 12px;
                }

                .dialog-actions button {
                    padding: 16px;
                    border-radius: 12px;
                    font-size: 1rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    border: none;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 4px;
                }

                .dialog-actions button:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }

                .btn-stop {
                    background: rgba(255, 255, 255, 0.1);
                    color: #fff;
                    border: 1px solid rgba(255, 255, 255, 0.2) !important;
                }

                .btn-stop:hover:not(:disabled) {
                    background: rgba(255, 255, 255, 0.15);
                }

                .btn-continue {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }

                .btn-continue:hover:not(:disabled) {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }

                .btn-hint {
                    font-size: 0.75rem;
                    font-weight: 400;
                    opacity: 0.7;
                }
            `}</style>
        </div>
    );
}

function getScoreLevel(score: string): string {
    const numScore = parseInt(score, 10);
    if (isNaN(numScore)) return "medium";
    if (numScore < 25) return "critical";
    if (numScore < 50) return "low";
    if (numScore < 75) return "medium";
    return "high";
}

function getScoreDescription(score: string): string {
    const numScore = parseInt(score, 10);
    if (isNaN(numScore)) return "Unable to determine security score.";
    if (numScore < 25) {
        return "Critical security issues detected. This app has severe vulnerabilities that should be addressed immediately.";
    }
    if (numScore < 50) {
        return "Multiple security concerns found. The app has significant issues that need attention.";
    }
    if (numScore < 75) {
        return "Moderate security posture. Some issues were found that should be reviewed.";
    }
    return "Good security posture. Few issues detected, but dynamic analysis may reveal more.";
}

export default MobSFDecisionDialog;
