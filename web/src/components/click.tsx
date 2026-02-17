import { useState } from "react";

export default function Click() {
  const [count, setCount] = useState(0);

  return (
    <div className="flex flex-col">
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
        Click me
      </button>
    </div>
  );

}