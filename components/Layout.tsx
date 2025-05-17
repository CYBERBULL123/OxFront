import React, { useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import { Home, Brain, Image, Database, Menu, X, LogOut, User, BarChart2, Moon, Sun, BookOpen } from 'lucide-react'
import { logout } from '@/lib/api' // Import logout function

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [darkMode, setDarkMode] = useState(false)
  const router = useRouter()

  useEffect(() => {
    const isDarkMode = localStorage.getItem('darkMode') === 'true'
    setDarkMode(isDarkMode)
    document.documentElement.classList.toggle('dark', isDarkMode)
  }, [])

  const toggleDarkMode = () => {
    const newDarkMode = !darkMode
    setDarkMode(newDarkMode)
    localStorage.setItem('darkMode', newDarkMode.toString())
    document.documentElement.classList.toggle('dark', newDarkMode)
  }

  const menuItems = [
    { name: 'Dashboard', icon: BarChart2, href: '/dashboard' },
    { name: 'OxIntell', icon: Brain, href: '/oxintell' },
    { name: 'OxImaGen', icon: Image, href: '/oximage' },
    { name: 'OxRAG', icon: Database, href: '/oxrag' },
    { name: 'Profile', icon: User, href: '/profile' },
    { name: 'Documentation', icon: BookOpen, href: '/docs' },
  ]

  const handleLogout = async () => {
    // Use our logout function to clear tokens and redirect
    await logout();
    // The logout function already handles the redirect
  }

  return (
    <div className={`flex h-screen bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-white transition-colors duration-200`}>
      <motion.nav
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-800 transform ${
          isMenuOpen ? 'translate-x-0' : '-translate-x-full'
        } transition-transform duration-300 ease-in-out lg:relative lg:translate-x-0`}
        initial={false}
        animate={isMenuOpen ? 'open' : 'closed'}
      >
        <div className="flex items-center justify-between p-4 border-b dark:border-gray-700">
          <Link href="/" className="text-2xl font-bold text-blue-600 dark:text-blue-400">OxSuite</Link>
          <button onClick={() => setIsMenuOpen(false)} className="lg:hidden">
            <X size={24} />
          </button>
        </div>
        <ul className="mt-8">
          {menuItems.map((item) => (
            <li key={item.name} className="mb-2">
              <Link href={item.href} className="flex items-center px-4 py-2 text-gray-700 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-700 transition-colors duration-200">
                <item.icon className="mr-3" size={20} />
                {item.name}
              </Link>
            </li>
          ))}
        </ul>
        <div className="absolute bottom-0 w-full p-4 border-t dark:border-gray-700">
          <button
            onClick={toggleDarkMode}
            className="flex items-center justify-center w-full px-4 py-2 text-sm font-medium text-gray-700 bg-gray-200 rounded-md hover:bg-gray-300 dark:text-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 transition-colors duration-200"
          >
            {darkMode ? <Sun size={16} className="mr-2" /> : <Moon size={16} className="mr-2" />}
            {darkMode ? 'Light Mode' : 'Dark Mode'}
          </button>
          <button
            onClick={handleLogout}
            className="flex items-center justify-center w-full px-4 py-2 mt-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700 transition-colors duration-200"
          >
            <LogOut size={16} className="mr-2" />
            Logout
          </button>
        </div>
      </motion.nav>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="bg-white dark:bg-gray-800 lg:hidden">
          <div className="flex items-center p-4">
            <button onClick={() => setIsMenuOpen(true)} className="text-gray-500 hover:text-gray-600 dark:text-gray-400 dark:hover:text-gray-300">
              <Menu size={24} />
            </button>
            <h1 className="ml-4 text-xl font-semibold">OxSuite</h1>
          </div>
        </header>
        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-gray-100 dark:bg-gray-900">
          <div className="container mx-auto px-6 py-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

export default Layout

