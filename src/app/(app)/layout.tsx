import { Sidebar } from "@/components/nav/sidebar";
import { TopBar } from "@/components/nav/topbar";
import { requireUser } from "@/lib/auth/dal";

export default async function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // The real gate. proxy.ts only checks that a cookie exists; this verifies it.
  const user = await requireUser();

  return (
    <div className="flex h-dvh overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar user={user} />
        <main className="flex-1 overflow-y-auto p-5">{children}</main>
      </div>
    </div>
  );
}
