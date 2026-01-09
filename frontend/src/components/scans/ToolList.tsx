"use client";

import React from "react";
import { ToolKey } from "@/services/api";
import { ToolExecution, ScanVulnerability } from "@/context/ScanContext";
import { ToolRow } from "./ToolRow";

interface ToolListProps {
    tools: Record<ToolKey, ToolExecution>;
    target: string;
    vulnerabilities: ScanVulnerability[];
}

export function ToolList({ tools, target, vulnerabilities }: ToolListProps) {
    // Sort tools (optional, keep order consistent)
    const sortedKeys = Object.keys(tools) as ToolKey[];

    return (
        <div className="flex flex-col gap-4">
            {/* List Header */}
            <div className="hidden md:flex items-center px-4 mb-2 text-xs font-bold text-slate-500 uppercase tracking-wider">
                <div className="w-10"></div>
                <div className="w-48">Scanner</div>
                <div className="flex-1 px-4">Target</div>
                <div className="w-32">Status</div>
                <div className="w-24 text-right px-4">Duration</div>
                <div className="w-32 text-right px-4">Risks</div>
                <div className="w-10"></div>
            </div>

            {sortedKeys.map((key) => (
                <ToolRow
                    key={key}
                    tool={key}
                    data={tools[key]}
                    target={target}
                    vulnerabilities={vulnerabilities}
                />
            ))}
        </div>
    );
}
