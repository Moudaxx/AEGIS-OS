use chrono::{DateTime, Utc};

// ─── Robot Command ───
#[derive(Debug, Clone)]
pub struct RobotCommand {
    pub command_id: String,
    pub robot_id: String,
    pub command_type: CommandType,
    pub parameters: Vec<f64>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandType {
    Move,
    Stop,
    Rotate,
    GripperOpen,
    GripperClose,
    Navigate,
    EmergencyStop,
}

// ─── Safety Check Result ───
#[derive(Debug, PartialEq)]
pub enum SafetyResult {
    Safe,
    Blocked { reason: String },
    LimitApplied { original: f64, limited: f64 },
}

// ─── ROS2 Gatekeeper ───
pub struct Ros2Gatekeeper {
    max_velocity: f64,
    max_acceleration: f64,
    geofence_radius: f64,
    emergency_stop_active: bool,
    enabled: bool,
    command_log: Vec<RobotCommand>,
}

impl Ros2Gatekeeper {
    pub fn new() -> Self {
        println!("[ROS2] Gatekeeper initialized");
        Ros2Gatekeeper {
            max_velocity: 1.0,
            max_acceleration: 0.5,
            geofence_radius: 10.0,
            emergency_stop_active: false,
            enabled: false,
            command_log: Vec::new(),
        }
    }

    pub fn enable(&mut self) {
        // Check if ROS2 is available
        let ros_available = std::env::var("ROS_DISTRO").is_ok();
        if ros_available {
            self.enabled = true;
            println!("[ROS2] Gatekeeper ENABLED | ROS2 detected");
        } else {
            println!("[ROS2] ROS2 not detected — running in simulation mode");
            self.enabled = true; // Still enable for simulation
        }
    }

    // Check velocity limits
    pub fn check_velocity(&self, velocity: f64) -> SafetyResult {
        if self.emergency_stop_active {
            return SafetyResult::Blocked {
                reason: "Emergency stop active".to_string(),
            };
        }

        if velocity.abs() > self.max_velocity {
            let limited = velocity.signum() * self.max_velocity;
            println!("[ROS2] Velocity limited: {:.2} -> {:.2} m/s", velocity, limited);
            return SafetyResult::LimitApplied {
                original: velocity,
                limited,
            };
        }
        SafetyResult::Safe
    }

    // Check geofence
    pub fn check_geofence(&self, x: f64, y: f64) -> SafetyResult {
        let distance = (x * x + y * y).sqrt();
        if distance > self.geofence_radius {
            println!("[ROS2] GEOFENCE BLOCKED: ({:.1}, {:.1}) distance={:.1} > radius={:.1}",
                x, y, distance, self.geofence_radius);
            return SafetyResult::Blocked {
                reason: format!("Outside geofence: {:.1}m > {:.1}m", distance, self.geofence_radius),
            };
        }
        SafetyResult::Safe
    }

    // Validate and process command
    pub fn process_command(&mut self, cmd: RobotCommand) -> SafetyResult {
        if !self.enabled {
            return SafetyResult::Blocked {
                reason: "Gatekeeper not enabled".to_string(),
            };
        }

        if self.emergency_stop_active && cmd.command_type != CommandType::EmergencyStop {
            println!("[ROS2] BLOCKED: Emergency stop active — only E-Stop allowed");
            return SafetyResult::Blocked {
                reason: "Emergency stop active".to_string(),
            };
        }

        // Handle emergency stop
        if cmd.command_type == CommandType::EmergencyStop {
            self.emergency_stop_active = true;
            println!("[ROS2] EMERGENCY STOP ACTIVATED for robot: {}", cmd.robot_id);
            self.command_log.push(cmd);
            return SafetyResult::Safe;
        }

        // Check velocity for move commands
        if cmd.command_type == CommandType::Move || cmd.command_type == CommandType::Navigate {
            if let Some(&vel) = cmd.parameters.first() {
                let vel_check = self.check_velocity(vel);
                if vel_check != SafetyResult::Safe {
                    return vel_check;
                }
            }
        }

        // Check geofence for navigate commands
        if cmd.command_type == CommandType::Navigate {
            if cmd.parameters.len() >= 3 {
                let geo_check = self.check_geofence(cmd.parameters[1], cmd.parameters[2]);
                if geo_check != SafetyResult::Safe {
                    return geo_check;
                }
            }
        }

        println!("[ROS2] Command APPROVED: {:?} for robot {}", cmd.command_type, cmd.robot_id);
        self.command_log.push(cmd);
        SafetyResult::Safe
    }

    pub fn reset_emergency(&mut self) {
        self.emergency_stop_active = false;
        println!("[ROS2] Emergency stop RESET");
    }

    pub fn set_limits(&mut self, max_vel: f64, max_accel: f64, geofence: f64) {
        self.max_velocity = max_vel;
        self.max_acceleration = max_accel;
        self.geofence_radius = geofence;
        println!("[ROS2] Limits updated: vel={:.1} accel={:.1} geofence={:.1}m",
            max_vel, max_accel, geofence);
    }

    pub fn status(&self) {
        println!("[ROS2] Enabled: {} | E-Stop: {} | Commands: {} | Vel: {:.1} | Geofence: {:.1}m",
            self.enabled, self.emergency_stop_active, self.command_log.len(),
            self.max_velocity, self.geofence_radius);
    }
}