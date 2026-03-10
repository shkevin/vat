"use client";

import { GripVertical } from "lucide-react";
import * as ResizablePrimitive from "react-resizable-panels";

const ResizablePanelGroup = ResizablePrimitive.PanelGroup;
const ResizablePanel = ResizablePrimitive.Panel;

function ResizableHandle({
  withHandle,
  style,
  ...props
}: React.ComponentProps<typeof ResizablePrimitive.PanelResizeHandle> & {
  withHandle?: boolean;
}) {
  return (
    <ResizablePrimitive.PanelResizeHandle
      style={{
        position: "relative",
        width: 6,
        minWidth: 6,
        background: "transparent",
        cursor: "col-resize",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        ...style,
      }}
      {...props}
    >
      {withHandle && (
        <div
          style={{
            width: 4,
            height: 24,
            borderRadius: 2,
            background: "#334155",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <GripVertical size={12} style={{ color: "#64748b" }} />
        </div>
      )}
    </ResizablePrimitive.PanelResizeHandle>
  );
}

export { ResizablePanelGroup, ResizablePanel, ResizableHandle };
export type { ImperativePanelHandle } from "react-resizable-panels";
