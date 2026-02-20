import { useEffect, useState } from "react";
import { apiRequest, APIError } from "../utils/api";
import PageShell from "./PageShell";

interface User {
  id: string;
  username: string;
  email: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
}

interface Message {
  text: string;
  variant: "info" | "success" | "error";
}

const emptyMessage: Message = { text: "", variant: "info" };

export default function RolesUserBinding() {
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<string>("");
  const [selectedRoleId, setSelectedRoleId] = useState<string>("");
  const [message, setMessage] = useState<Message>(emptyMessage);
  const [isLoading, setIsLoading] = useState(false);
  const [userRoles, setUserRoles] = useState<Role[]>([]);

  useEffect(() => {
    loadUsers();
    loadRoles();
  }, []);

  const loadUsers = async () => {
    try {
      const data = await apiRequest<User[]>("/users");
      setUsers(data);
    } catch (error) {
      console.warn("Failed to load users");
      setUsers([]);
    }
  };

  const loadRoles = async () => {
    try {
      const data = await apiRequest<Role[]>("/roles");
      setRoles(data);
    } catch (error) {
      console.warn("Failed to load roles");
      setRoles([]);
    }
  };

  const loadUserRoles = async (userId: string) => {
    if (!userId) {
      setUserRoles([]);
      return;
    }
    try {
      const data = await apiRequest<Role[]>(`/users/${userId}/roles`);
      setUserRoles(data);
    } catch (error) {
      console.warn("Failed to load user roles");
      setUserRoles([]);
    }
  };

  const handleUserChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const userId = e.target.value;
    setSelectedUserId(userId);
    loadUserRoles(userId);
  };

  const handleAssignRole = async () => {
    if (!selectedUserId || !selectedRoleId) {
      setMessage({ text: "Please select both user and role", variant: "error" });
      return;
    }

    setMessage({ text: "Assigning role...", variant: "info" });
    setIsLoading(true);

    try {
      // Get current roles for the user
      const currentRoles = await apiRequest<Role[]>(`/users/${selectedUserId}/roles`);
      const roleIds = currentRoles.map((r) => r.id);

      // Add new role if not already assigned
      if (!roleIds.includes(selectedRoleId)) {
        roleIds.push(selectedRoleId);
      }

      // Assign all roles
      await apiRequest(`/users/${selectedUserId}/roles`, {
        method: "POST",
        body: JSON.stringify({ role_ids: roleIds }),
      });

      setMessage({ text: "Role assigned successfully", variant: "success" });
      setSelectedRoleId("");
      await loadUserRoles(selectedUserId);
    } catch (error) {
      setMessage({
        text: error instanceof Error ? error.message : "Failed to assign role",
        variant: "error",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleRemoveRole = async (roleId: string) => {
    if (!selectedUserId) return;

    setMessage({ text: "Removing role...", variant: "info" });
    setIsLoading(true);

    try {
      // Get current roles for the user
      const currentRoles = await apiRequest<Role[]>(`/users/${selectedUserId}/roles`);
      const roleIds = currentRoles.filter((r) => r.id !== roleId).map((r) => r.id);

      // Assign remaining roles
      await apiRequest(`/users/${selectedUserId}/roles`, {
        method: "POST",
        body: JSON.stringify({ role_ids: roleIds }),
      });

      setMessage({ text: "Role removed successfully", variant: "success" });
      await loadUserRoles(selectedUserId);
    } catch (error) {
      setMessage({
        text: error instanceof Error ? error.message : "Failed to remove role",
        variant: "error",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <PageShell
      title="User-Role Binding"
      subtitle="Manage user roles and permissions"
      actions={
        <button
          type="button"
          onClick={() => {
            loadUsers();
            loadRoles();
          }}
          className="rounded-2xl border border-amber-200 px-4 py-2 text-sm font-semibold text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
        >
          Refresh
        </button>
      }
    >
      <section className="rounded-3xl border border-amber-100 bg-white/95 p-6  shadow-amber-100/40 dark:border-slate-800 dark:bg-slate-900/70">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
          Assign Roles to User
        </h2>

        {message.text && (
          <div
            className={`mt-4 rounded-lg px-4 py-2 text-sm ${
              message.variant === "success"
                ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300"
                : message.variant === "error"
                  ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                  : "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300"
            }`}
          >
            {message.text}
          </div>
        )}

        <div className="mt-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
              Select User (ID: {selectedUserId})
            </label>
            <select
              value={selectedUserId}
              onChange={handleUserChange}
              className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-4 py-2 dark:border-slate-600 dark:bg-slate-800"
            >
              <option value="">-- Choose a user --</option>
              {users.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.username} ({user.email})
                </option>
              ))}
            </select>
          </div>

          {selectedUserId && (
            <>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Select Role to Add
                </label>
                <select
                  value={selectedRoleId}
                  onChange={(e) => setSelectedRoleId(e.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-4 py-2 dark:border-slate-600 dark:bg-slate-800"
                >
                  <option value="">-- Choose a role --</option>
                  {roles.map((role) => (
                    <option key={role.id} value={role.id}>
                      {role.name} - {role.description}
                    </option>
                  ))}
                </select>
              </div>

              <button
                onClick={handleAssignRole}
                disabled={isLoading || !selectedRoleId}
                className="rounded-lg bg-amber-600 px-4 py-2 text-white transition hover:bg-amber-700 disabled:bg-gray-400 dark:bg-amber-700 dark:hover:bg-amber-800"
              >
                {isLoading ? "Assigning..." : "Add Role"}
              </button>

              <div className="mt-6">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  Current Roles for {users.find((u) => u.id === selectedUserId)?.username}
                </h3>
                {userRoles.length === 0 ? (
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                    No roles assigned
                  </p>
                ) : (
                  <ul className="mt-2 space-y-2">
                    {userRoles.map((role) => (
                      <li
                        key={role.id}
                        className="flex items-center justify-between rounded-lg bg-slate-100 px-4 py-2 dark:bg-slate-800"
                      >
                        <div>
                          <p className="font-medium text-slate-900 dark:text-slate-100">
                            {role.name}
                          </p>
                          <p className="text-xs text-slate-600 dark:text-slate-400">
                            {role.description}
                          </p>
                        </div>
                        <button
                          onClick={() => handleRemoveRole(role.id)}
                          disabled={isLoading}
                          className="rounded-lg bg-red-600 px-3 py-1 text-xs text-white transition hover:bg-red-700 disabled:bg-gray-400"
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </>
          )}
        </div>
      </section>
    </PageShell>
  );
}
