import { useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import logoSlythestx from '../assets/slythestx.png';

export default function Layout() {
  const location = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const navigation = [
    {
      name: 'Dashboard',
      href: '/',
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
        </svg>
      ),
    },
    {
      name: 'Scans',
      href: '/scans',
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      name: 'Devices',
      href: '/devices',
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
        </svg>
      ),
    },
    {
      name: 'Settings',
      href: '/settings',
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      ),
    },
  ];

  const isActive = (href: string) =>
    href === '/' ? location.pathname === '/' : location.pathname.startsWith(href);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white flex overflow-hidden">

      {/* Sidebar */}
	<aside
	  className={`${sidebarCollapsed ? 'w-20' : 'w-64'}
	  shrink-0 fixed h-full z-10
	  bg-[#12121a] border-r border-gray-800
	  flex flex-col transition-all duration-300`}
	>
	  <div className="h-16 flex items-center justify-center border-b border-gray-800 px-4">
	    <div className="flex items-center gap-3">
	      <div className="w-12 h-12 flex items-center justify-center overflow-hidden">
		<img 
		  src={logoSlythestx} 
		  alt="Slythestx Logo"
		  className="w-full h-full object-contain" 
		/>
	      </div>

	      {!sidebarCollapsed && (
		<span className="text-xl font-black tracking-wider bg-gradient-to-r from-green-400 to-emerald-600 bg-clip-text text-transparent uppercase">
		  Slythestx
		</span>
	      )}
	    </div>
	  </div>

	  <nav className="flex-1 py-6 px-3 space-y-2">
	    {navigation.map((item) => (
	      <Link
		key={item.name}
		to={item.href}
		className={`flex items-center gap-3 px-4 py-3 rounded-xl transition
		  ${isActive(item.href)
		    ? 'bg-gradient-to-r from-green-500/10 to-emerald-500/10 text-green-400 border border-green-500/20'
		    : 'text-gray-400 hover:text-white hover:bg-white/5'
		  }`}
	      >
		{item.icon}
		{!sidebarCollapsed && <span className="font-medium">{item.name}</span>}
	      </Link>
	    ))}
	  </nav>

	  <div className="p-4 border-t border-gray-800">
	    <button
	      onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
	      className="w-full flex justify-center py-2 text-gray-400 hover:text-white hover:bg-white/5 rounded-lg"
	    >
	      {sidebarCollapsed ? '→' : '←'}
	    </button>
	  </div>
	</aside>

      {/* MAIN CONTENT*/}
      <main
        className={`flex-1 min-w-0 overflow-x-hidden
        ${sidebarCollapsed ? 'ml-20' : 'ml-64'}
        transition-all duration-300`}
      >
        <Outlet />
      </main>
    </div>
  );
}
