@app.post("/api/demo/load")
def load_demo(db: Session = Depends(get_db)):
    from datetime import timedelta

    try:
        now = datetime.now(timezone.utc)

        demo = [
            Event(
                timestamp=now - timedelta(minutes=5),
                source="windows",
                event_type="login_failed",
                event_id="4625",
                username="administrator",
                source_ip="10.10.10.50",
                message="Failed logon"
            ),
            Event(
                timestamp=now - timedelta(minutes=4),
                source="windows",
                event_type="login_failed",
                event_id="4625",
                username="administrator",
                source_ip="10.10.10.50",
                message="Failed logon"
            ),
            Event(
                timestamp=now - timedelta(minutes=3),
                source="windows",
                event_type="login_failed",
                event_id="4625",
                username="administrator",
                source_ip="10.10.10.50",
                message="Failed logon"
            ),
            Event(
                timestamp=now - timedelta(minutes=2),
                source="windows",
                event_type="login_failed",
                event_id="4625",
                username="administrator",
                source_ip="10.10.10.50",
                message="Failed logon"
            ),
            Event(
                timestamp=now - timedelta(minutes=1),
                source="windows",
                event_type="login_failed",
                event_id="4625",
                username="administrator",
                source_ip="10.10.10.50",
                message="Failed logon"
            ),
            Event(
                timestamp=now,
                source="windows",
                event_type="login_success",
                event_id="4624",
                username="administrator",
                source_ip="10.10.10.50",
                message="Successful logon"
            ),
            Event(
                timestamp=now + timedelta(seconds=30),
                source="windows",
                event_type="process_start",
                event_id="4688",
                username="administrator",
                source_ip="10.10.10.50",
                process="powershell.exe",
                command="powershell.exe -enc UABvAHcAZQByAFMAaABlAGwAbA==",
                message="PowerShell started"
            )
        ]

        db.add_all(demo)
        db.commit()

        created = run_detection(db)

        return {
            "events_added": len(demo),
            "alerts_created": created
        }

    except Exception as e:
        db.rollback()

        print("DEMO LOAD ERROR:", repr(e))

        raise HTTPException(
            status_code=500,
            detail=f"Demo load failed: {str(e)}"
        )
